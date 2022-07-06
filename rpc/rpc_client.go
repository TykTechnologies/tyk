package rpc

import (
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk-pump/serializer"

	"github.com/cenkalti/backoff/v4"
	"github.com/gocraft/health"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"

	"github.com/TykTechnologies/gorpc"
)

var (
	GlobalRPCCallTimeout = 30 * time.Second
	GlobalRPCPingTimeout = 60 * time.Second
	Log                  = &logrus.Logger{}
	Instrument           *health.Stream

	clientSingleton     *gorpc.Client
	clientSingletonMu   sync.Mutex
	funcClientSingleton *gorpc.DispatcherClient

	dispatcher = gorpc.NewDispatcher()
	addedFuncs = make(map[string]bool)

	getGroupLoginCallback       func(string, string) interface{}
	emergencyModeCallback       func()
	emergencyModeLoadedCallback func()

	killChan = make(chan int)
	killed   bool
	id       string

	rpcLoginMu sync.Mutex

	rpcConnectMu sync.Mutex

	// UseSyncLoginRPC for tests where we dont need to execute as a goroutine
	UseSyncLoginRPC bool

	AnalyticsSerializers []serializer.AnalyticsSerializer
)

// ErrRPCIsDown this is returned when we can't reach rpc server.
var ErrRPCIsDown = errors.New("RPCStorageHandler: rpc is either down or was not configured")

// rpc.Login is callend may places we only need one in flight at a time.
var loginFlight singleflight.Group

var values rpcOpts

type rpcOpts struct {
	// This tracks how many times have successfully logged. If this is 0 then we
	// are in cold start.
	loadCounts          atomic.Value
	emergencyMode       atomic.Value
	emergencyModeLoaded atomic.Value
	config              atomic.Value
	clientIsConnected   atomic.Value
}

func (r rpcOpts) ClientIsConnected() bool {
	if v := r.clientIsConnected.Load(); v != nil {
		return v.(bool)
	}
	return false
}

func (r rpcOpts) Config() Config {
	if v := r.config.Load(); v != nil {
		return v.(Config)
	}
	return Config{}
}

func (r *rpcOpts) Reset() {
	r.loadCounts.Store(0)
	r.emergencyMode.Store(false)
	r.emergencyModeLoaded.Store(false)
	r.clientIsConnected.Store(false)
}

func (r *rpcOpts) SetLoadCounts(n int) {
	r.loadCounts.Store(n)
}

func (r *rpcOpts) IncrLoadCounts(n int) {
	if v := r.loadCounts.Load(); v != nil {
		r.loadCounts.Store(v.(int) + n)
	} else {
		r.loadCounts.Store(n)
	}
}

func (r *rpcOpts) GetLoadCounts() int {
	if v := r.loadCounts.Load(); v != nil {
		return v.(int)
	}
	return 0
}

func (r *rpcOpts) SetEmergencyMode(n bool) {
	r.emergencyMode.Store(n)
}

func (r *rpcOpts) GetEmergencyMode() bool {
	if v := r.emergencyMode.Load(); v != nil {
		return v.(bool)
	}
	return false
}

func (r *rpcOpts) SetEmergencyModeLoaded(n bool) {
	r.emergencyModeLoaded.Store(n)
}

func (r *rpcOpts) GetEmergencyModeLoaded() bool {
	if v := r.emergencyModeLoaded.Load(); v != nil {
		return v.(bool)
	}
	return false
}

const (
	ClientSingletonCall     = "gorpcClientCall"
	FuncClientSingletonCall = "gorpcDispatcherClientCall"
)

type Config struct {
	UseSSL                bool   `json:"use_ssl"`
	SSLInsecureSkipVerify bool   `json:"ssl_insecure_skip_verify"`
	SSLMinVersion         uint16 `json:"ssl_min_version"`
	SSLMaxVersion         uint16 `json:"ssl_max_version"`
	ConnectionString      string `json:"connection_string"`
	RPCKey                string `json:"rpc_key"`
	APIKey                string `json:"api_key"`
	GroupID               string `json:"group_id"`
	CallTimeout           int    `json:"call_timeout"`
	PingTimeout           int    `json:"ping_timeout"`
	RPCPoolSize           int    `json:"rpc_pool_size"`
}

func IsEmergencyMode() bool {
	return values.GetEmergencyMode()
}

func LoadCount() int {
	return values.GetLoadCounts()
}

func Reset() {
	clientSingleton.Stop()
	clientSingleton = nil
	funcClientSingleton = nil
	values.Reset()
}

func ResetEmergencyMode() {
	values.SetEmergencyMode(false)
	values.SetEmergencyModeLoaded(false)
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
	if Instrument == nil {
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

	values.config.Store(connConfig)
	getGroupLoginCallback = getGroupLoginFunc
	emergencyModeCallback = emergencyModeFunc
	emergencyModeLoadedCallback = emergencyModeLoadedFunc

	if values.ClientIsConnected() {
		Log.Debug("Using RPC singleton for connection")
		return true
	}

	if clientSingleton != nil {
		return !values.GetEmergencyMode()
	}

	// RPC Client is unset
	// Set up the cache
	Log.Info("Setting new RPC connection!")

	connID := uuid.NewV4().String()

	// Length should fit into 1 byte. Protection if we decide change uuid in future.
	if len(connID) > 255 {
		panic("connID is too long")
	}

	if values.Config().UseSSL {
		clientCfg := &tls.Config{
			InsecureSkipVerify: values.Config().SSLInsecureSkipVerify,
			MinVersion:         values.Config().SSLMinVersion,
			MaxVersion:         values.Config().SSLMaxVersion,
		}

		clientSingleton = gorpc.NewTLSClient(values.Config().ConnectionString, clientCfg)
	} else {
		clientSingleton = gorpc.NewTCPClient(values.Config().ConnectionString)
	}

	if Log.Level != logrus.DebugLevel {
		clientSingleton.LogError = gorpc.NilErrorLogger
	}

	clientSingleton.OnConnect = onConnectFunc

	clientSingleton.Conns = values.Config().RPCPoolSize
	if clientSingleton.Conns == 0 {
		clientSingleton.Conns = 20
	}

	clientSingleton.Dial = func(addr string) (conn net.Conn, err error) {

		dialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}

		useSSL := values.Config().UseSSL

		if useSSL {
			cfg := &tls.Config{
				InsecureSkipVerify: values.Config().SSLInsecureSkipVerify,
				MinVersion:         values.Config().SSLMinVersion,
				MaxVersion:         values.Config().SSLMaxVersion,
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

	handleLogin()
	if !suppressRegister {
		register()
		go checkDisconnect()
	}
	return true
}

func handleLogin() {
	if UseSyncLoginRPC == true {
		Login()
		return
	}
	go Login()
}

// Login tries to login to the rpc sever. Returns true if it succeeds and false
// if it fails.
func Login() bool {
	// I know this is extreme but rpc.Login() appears about 17 times and the
	// methods appears to be sometimes called in goroutines.
	//
	// Unless someone audits to ensure all of where this appears the parent calls
	// are not concurrent, this is a much safer solution.
	v, _, _ := loginFlight.Do("Login", func() (interface{}, error) {
		return loginBase(), nil
	})
	return v.(bool)
}

func loginBase() bool {
	if !doLoginWithRetries(login, groupLogin, hasAPIKey, isGroup) {
		rpcLoginMu.Lock()
		if values.GetLoadCounts() == 0 && !values.GetEmergencyModeLoaded() {
			Log.Warning("[RPC Store] --> Detected cold start, attempting to load from cache")
			Log.Warning("[RPC Store] ----> Found APIs... beginning emergency load")
			values.SetEmergencyModeLoaded(true)
			if emergencyModeLoadedCallback != nil {
				go emergencyModeLoadedCallback()
			}
		}
		rpcLoginMu.Unlock()
		return false
	}
	return true
}

func GroupLogin() bool {
	return doGroupLogin(groupLogin)
}

func doGroupLogin(login func() error) bool {
	if getGroupLoginCallback == nil {
		Log.Error("GroupLogin call back is not set")
		return false
	}
	b := backoff.WithMaxRetries(backoff.NewExponentialBackOff(), 3)
	return backoff.Retry(recoverOp(login), b) == nil
}

func groupLogin() error {
	groupLoginData := getGroupLoginCallback(values.Config().APIKey, values.Config().GroupID)
	ok, err := FuncClientSingleton("LoginWithGroup", groupLoginData)
	if err != nil {
		Log.WithError(err).Error("RPC Login failed")
		EmitErrorEventKv(
			FuncClientSingletonCall,
			"LoginWithGroup",
			err,
			map[string]string{
				"GroupID": values.Config().GroupID,
			},
		)
		return err
	}
	if ok == false {
		Log.Error("RPC Login incorrect")
		return errLogFailed
	}
	Log.Debug("[RPC Store] Group Login complete")
	values.IncrLoadCounts(1)
	return nil
}

var errLogFailed = errors.New("Login incorrect")

func login() error {
	k, err := FuncClientSingleton("Login", values.Config().APIKey)
	if err != nil {
		Log.WithError(err).Error("RPC Login failed")
		EmitErrorEvent(FuncClientSingletonCall, "Login", err)
		return err
	}
	ok := k.(bool)
	if !ok {
		Log.Error("RPC Login incorrect")
		return errLogFailed
	}
	Log.Debug("[RPC Store] Login complete")
	values.IncrLoadCounts(1)
	return nil
}

func hasAPIKey() bool {
	return len(values.Config().APIKey) != 0
}

func isGroup() bool {
	return values.Config().GroupID != ""
}

// doLoginWithRetries uses login as a login function by calling it with retries
// until it succeeds or ultimately fail.
//
// hasAPIKey is called to check whether config.APIKey is set if this function
// returns false we exit the process.
//
// isGroup returns true if the config.GroupID is set. If this returns true then
// we perform group login.
func doLoginWithRetries(login, group func() error, hasAPIKey, isGroup func() bool) bool {
	Log.Debug("[RPC Store] Login initiated")

	if !hasAPIKey() {
		Log.Fatal("No API Key set!")
	}
	// If we have a group ID, lets login as a group
	if isGroup() {
		return doGroupLogin(group)
	}
	b := backoff.WithMaxRetries(backoff.NewExponentialBackOff(), 3)
	return backoff.Retry(recoverOp(login), b) == nil
}

func recoverOp(fn func() error) func() error {
	n := 0
	return func() error {
		err := fn()
		if err != nil {
			if n == 0 {
				// we failed at our first call so we are in emergency mode now
				values.SetEmergencyMode(true)
			}
			n++
			return err
		}
		if values.GetEmergencyMode() {
			values.SetEmergencyMode(false)
			values.SetEmergencyModeLoaded(false)
			if emergencyModeCallback != nil {
				emergencyModeCallback()
			}
		}
		return nil
	}
}

// FuncClientSingleton performs RPC call. This might be called before we have
// established RPC connection, in that case we perform a retry with exponential
// backoff ensuring indeed we can't connect to the rpc, this will eventually
// fall into emergency mode( That is handled outside of this function call)
func FuncClientSingleton(funcName string, request interface{}) (result interface{}, err error) {
	be := backoff.Retry(func() error {
		if !values.ClientIsConnected() {
			return ErrRPCIsDown
		}
		result, err = funcClientSingleton.CallTimeout(funcName, request, GlobalRPCCallTimeout)
		return nil
	}, backoff.WithMaxRetries(
		backoff.NewConstantBackOff(10*time.Millisecond), 3,
	))
	if be != nil {
		err = be
	}
	return
}

var rpcConnectionsPool []net.Conn

func onConnectFunc(conn net.Conn) (net.Conn, string, error) {
	values.clientIsConnected.Store(true)
	remoteAddr := conn.RemoteAddr().String()
	Log.WithField("remoteAddr", remoteAddr).Debug("connected to RPC server")
	rpcConnectionsPool = append(rpcConnectionsPool, conn)
	return conn, remoteAddr, nil
}

func CloseConnections() {
	for k, v := range rpcConnectionsPool {
		err := v.Close()
		if err != nil {
			Log.WithError(err).Error("closing connection")
		} else {
			rpcConnectionsPool = append(rpcConnectionsPool[:k], rpcConnectionsPool[k+1:]...)
		}
	}
}

func Disconnect() bool {
	values.clientIsConnected.Store(false)
	return true
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

// ForceConnected only intended to be used in tests
// do not use it for any other thing
func ForceConnected(t *testing.T) {
	values.clientIsConnected.Store(true)
}

// SetEmergencyMode used in tests to force emergency mode
func SetEmergencyMode(t *testing.T, value bool) {
	values.SetEmergencyMode(value)
}
