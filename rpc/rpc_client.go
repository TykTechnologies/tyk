package rpc

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/gocraft/health"
	"github.com/lonelycode/gorpc"
	"github.com/satori/go.uuid"
)

var (
	GlobalRPCCallTimeout = 30 * time.Second
	GlobalRPCPingTimeout = 60 * time.Second
	Log                  = &logrus.Logger{}
	Instrument           *health.Stream

	clientSingleton     *gorpc.Client
	clientSingletonMu   sync.Mutex
	funcClientSingleton *gorpc.DispatcherClient
	clientIsConnected   bool

	dispatcher = gorpc.NewDispatcher()
	addedFuncs = make(map[string]bool)

	config                      Config
	getGroupLoginCallback       func(string, string) interface{}
	emergencyModeCallback       func()
	emergencyModeLoadedCallback func()

	// rpcLoadCount is a counter to check if this is a cold boot
	rpcLoadCount           int
	rpcEmergencyMode       bool
	rpcEmergencyModeLoaded bool

	killChan = make(chan int)
	killed   bool
	id       string

	rpcLoginMu     sync.Mutex
	reLoginRunning uint32

	rpcConnectMu sync.Mutex
)

const (
	ClientSingletonCall     = "gorpcClientCall"
	FuncClientSingletonCall = "gorpcDispatcherClientCall"
)

type Config struct {
	UseSSL                bool   `json:"use_ssl"`
	SSLInsecureSkipVerify bool   `json:"ssl_insecure_skip_verify"`
	ConnectionString      string `json:"connection_string"`
	RPCKey                string `json:"rpc_key"`
	APIKey                string `json:"api_key"`
	GroupID               string `json:"group_id"`
	CallTimeout           int    `json:"call_timeout"`
	PingTimeout           int    `json:"ping_timeout"`
	RPCPoolSize           int    `json:"rpc_pool_size"`
}

func IsEmergencyMode() bool {
	return rpcEmergencyMode
}

func LoadCount() int {
	return rpcLoadCount
}

func Reset() {
	clientSingleton.Stop()
	clientIsConnected = false
	clientSingleton = nil
	funcClientSingleton = nil
	rpcLoadCount = 0
	rpcEmergencyMode = false
	rpcEmergencyModeLoaded = false
}

func ResetEmergencyMode() {
	rpcEmergencyModeLoaded = false
	rpcEmergencyMode = false
}

func EmitErrorEvent(jobName string, funcName string, err error) {
	if Instrument == nil {
		return
	}

	job := Instrument.NewJob(jobName)
	if emitErr := job.EventErr(funcName, err); emitErr != nil {
		Log.WithError(emitErr).WithFields(logrus.Fields{
			"jobName":  jobName,
			"funcName": funcName,
		})
	}
}

func EmitErrorEventKv(jobName string, funcName string, err error, kv map[string]string) {
	if Instrument != nil {
		return
	}

	job := Instrument.NewJob(jobName)
	if emitErr := job.EventErrKv(funcName, err, kv); emitErr != nil {
		Log.WithError(emitErr).WithFields(logrus.Fields{
			"jobName":  jobName,
			"funcName": funcName,
			"kv":       kv,
		})
	}
}

// Connect will establish a connection to the RPC server specified in connection options
func Connect(connConfig Config, suppressRegister bool, dispatcherFuncs map[string]interface{},
	getGroupLoginFunc func(string, string) interface{},
	emergencyModeFunc func(),
	emergencyModeLoadedFunc func()) bool {
	rpcConnectMu.Lock()
	defer rpcConnectMu.Unlock()

	config = connConfig
	getGroupLoginCallback = getGroupLoginFunc
	emergencyModeCallback = emergencyModeFunc
	emergencyModeLoadedCallback = emergencyModeLoadedFunc

	if clientIsConnected {
		Log.Debug("Using RPC singleton for connection")
		return true
	}

	if clientSingleton != nil {
		return rpcEmergencyMode != true
	}

	// RPC Client is unset
	// Set up the cache
	Log.Info("Setting new RPC connection!")

	connID := uuid.NewV4().String()

	// Length should fit into 1 byte. Protection if we decide change uuid in future.
	if len(connID) > 255 {
		panic("connID is too long")
	}

	if config.UseSSL {
		clientCfg := &tls.Config{
			InsecureSkipVerify: config.SSLInsecureSkipVerify,
		}

		clientSingleton = gorpc.NewTLSClient(config.ConnectionString, clientCfg)
	} else {
		clientSingleton = gorpc.NewTCPClient(config.ConnectionString)
	}

	if Log.Level != logrus.DebugLevel {
		clientSingleton.LogError = gorpc.NilErrorLogger
	}

	clientSingleton.OnConnect = onConnectFunc

	clientSingleton.Conns = config.RPCPoolSize
	if clientSingleton.Conns == 0 {
		clientSingleton.Conns = 20
	}

	clientSingleton.Dial = func(addr string) (conn io.ReadWriteCloser, err error) {
		dialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}

		useSSL := config.UseSSL

		if useSSL {
			cfg := &tls.Config{
				InsecureSkipVerify: config.SSLInsecureSkipVerify,
			}

			conn, err = tls.DialWithDialer(dialer, "tcp", addr, cfg)
		} else {
			conn, err = dialer.Dial("tcp", addr)
		}

		if err != nil {
			EmitErrorEventKv(
				ClientSingletonCall,
				"dial",
				err,
				map[string]string{
					"addr":   addr,
					"useSSL": strconv.FormatBool(useSSL),
				},
			)
			return
		}

		conn.Write([]byte("proto2"))
		conn.Write([]byte{byte(len(connID))})
		conn.Write([]byte(connID))
		return conn, nil
	}
	clientSingleton.Start()

	loadDispatcher(dispatcherFuncs)

	if funcClientSingleton == nil {
		funcClientSingleton = dispatcher.NewFuncClient(clientSingleton)
	}

	if !Login() {
		return false
	}

	if !suppressRegister {
		register()
		go checkDisconnect()
	}

	return true
}

func reAttemptLogin(err error) bool {
	if atomic.LoadUint32(&reLoginRunning) == 1 {
		return false
	}
	atomic.StoreUint32(&reLoginRunning, 1)

	rpcLoginMu.Lock()
	if rpcLoadCount == 0 && !rpcEmergencyModeLoaded {
		Log.Warning("[RPC Store] --> Detected cold start, attempting to load from cache")
		Log.Warning("[RPC Store] ----> Found APIs... beginning emergency load")
		rpcEmergencyModeLoaded = true
		if emergencyModeLoadedCallback != nil {
			go emergencyModeLoadedCallback()
		}
	}
	rpcLoginMu.Unlock()

	time.Sleep(time.Second * 3)
	atomic.StoreUint32(&reLoginRunning, 0)

	if strings.Contains(err.Error(), "Cannot obtain response during timeout") {
		reConnect()
		return false
	}

	Log.Warning("[RPC Store] Login failed, waiting 3s to re-attempt")

	return Login()
}

func GroupLogin() bool {
	if getGroupLoginCallback == nil {
		Log.Error("GroupLogin call back is not set")
		return false
	}

	groupLoginData := getGroupLoginCallback(config.APIKey, config.GroupID)
	ok, err := FuncClientSingleton("LoginWithGroup", groupLoginData)
	if err != nil {
		Log.WithError(err).Error("RPC Login failed")
		EmitErrorEventKv(
			FuncClientSingletonCall,
			"LoginWithGroup",
			err,
			map[string]string{
				"GroupID": config.GroupID,
			},
		)
		rpcEmergencyMode = true
		go reAttemptLogin(err)
		return false
	}

	if ok == false {
		Log.Error("RPC Login incorrect")
		rpcEmergencyMode = true
		go reAttemptLogin(errors.New("Login incorrect"))
		return false
	}
	Log.Debug("[RPC Store] Group Login complete")
	rpcLoadCount++

	// Recovery
	if rpcEmergencyMode {
		rpcEmergencyMode = false
		rpcEmergencyModeLoaded = false
		if emergencyModeCallback != nil {
			emergencyModeCallback()
		}
	}

	return true
}

func Login() bool {
	Log.Debug("[RPC Store] Login initiated")

	if len(config.APIKey) == 0 {
		Log.Fatal("No API Key set!")
	}

	// If we have a group ID, lets login as a group
	if config.GroupID != "" {
		return GroupLogin()
	}

	ok, err := FuncClientSingleton("Login", config.APIKey)
	if err != nil {
		Log.WithError(err).Error("RPC Login failed")
		EmitErrorEvent(FuncClientSingletonCall, "Login", err)
		rpcEmergencyMode = true
		go reAttemptLogin(err)
		return false
	}

	if ok == false {
		Log.Error("RPC Login incorrect")
		rpcEmergencyMode = true
		go reAttemptLogin(errors.New("Login incorrect"))
		return false
	}
	Log.Debug("[RPC Store] Login complete")
	rpcLoadCount++

	if rpcEmergencyMode {
		rpcEmergencyMode = false
		rpcEmergencyModeLoaded = false
		if emergencyModeCallback != nil {
			emergencyModeCallback()
		}
	}

	return true
}

func FuncClientSingleton(funcName string, request interface{}) (interface{}, error) {
	return funcClientSingleton.CallTimeout(funcName, request, GlobalRPCCallTimeout)
}

func onConnectFunc(remoteAddr string, rwc io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	clientSingletonMu.Lock()
	defer clientSingletonMu.Unlock()

	clientIsConnected = true
	return rwc, nil
}

func Disconnect() bool {
	clientIsConnected = false
	return true
}

func reConnect() {
	// no-op, let the gorpc client handle it.
}

func register() {
	id = uuid.NewV4().String()
	Log.Debug("RPC Client registered")
}

func checkDisconnect() {
	res := <-killChan
	Log.WithField("res", res).Info("RPC Client disconnecting")
	killed = true
	Disconnect()
}

func loadDispatcher(dispatcherFuncs map[string]interface{}) {
	for funcName, funcBody := range dispatcherFuncs {
		if addedFuncs[funcName] {
			continue
		}
		dispatcher.AddFunc(funcName, funcBody)
		addedFuncs[funcName] = true
	}
}
