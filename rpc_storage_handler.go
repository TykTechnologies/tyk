package main

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/garyburd/redigo/redis"
	"github.com/lonelycode/gorpc"
	cache "github.com/pmylund/go-cache"
	"github.com/satori/go.uuid"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"

	"github.com/Sirupsen/logrus"
)

type InboundData struct {
	KeyName      string
	Value        string
	SessionState string
	Timeout      int64
	Per          int64
	Expire       int64
}

type DefRequest struct {
	OrgId string
	Tags  []string
}

type KeysValuesPair struct {
	Keys   []string
	Values []string
}

type GroupLoginRequest struct {
	UserKey string
	GroupID string
}

type GroupKeySpaceRequest struct {
	OrgID   string
	GroupID string
}

var (
	// rpcLoadCount is a counter to check if this is a cold boot
	rpcLoadCount           int
	rpcEmergencyMode       bool
	rpcEmergencyModeLoaded bool

	GlobalRPCCallTimeout time.Duration
	GlobalRPCPingTimeout time.Duration
)

// RPCStorageHandler is a storage manager that uses the redis database.
type RPCStorageHandler struct {
	KeyPrefix        string
	HashKeys         bool
	UserKey          string
	Address          string
	killChan         chan int
	Killed           bool
	Connected        bool
	ID               string
	SuppressRegister bool
}

func (r *RPCStorageHandler) Register() {
	r.ID = uuid.NewV4().String()
	r.killChan = make(chan int)
	log.Debug("RPC Client registered")
}

func (r *RPCStorageHandler) checkDisconnect() {
	res := <-r.killChan
	log.Info("RPC Client disconnecting: ", res)
	r.Killed = true
	r.Disconnect()
}

func (r *RPCStorageHandler) ReConnect() {
	// no-op, let the gorpc client handle it.
}

var RPCCLientSingleton *gorpc.Client
var RPCCLientSingletonMu sync.Mutex
var RPCFuncClientSingleton *gorpc.DispatcherClient
var RPCGlobalCache = cache.New(30*time.Second, 15*time.Second)
var RPCClientIsConnected bool

const (
	rpcCLientSingletonCall     = "gorpcClientCall"
	rpcFuncClientSingletonCall = "gorpcDispatcherClientCall"
)

func emitRPCErrorEvent(jobName string, funcName string, err error) {
	job := instrument.NewJob(jobName)
	if emitErr := job.EventErr(funcName, err); emitErr != nil {
		log.WithError(emitErr).WithFields(logrus.Fields{
			"jobName":  jobName,
			"funcName": funcName,
		})
	}
}

func emitRPCErrorEventKv(jobName string, funcName string, err error, kv map[string]string) {
	job := instrument.NewJob(jobName)
	if emitErr := job.EventErrKv(funcName, err, kv); emitErr != nil {
		log.WithError(emitErr).WithFields(logrus.Fields{
			"jobName":  jobName,
			"funcName": funcName,
			"kv":       kv,
		})
	}
}

var rpcConnectMu sync.Mutex

// Connect will establish a connection to the DB
func (r *RPCStorageHandler) Connect() bool {
	rpcConnectMu.Lock()
	defer rpcConnectMu.Unlock()

	if RPCClientIsConnected {
		log.Debug("Using RPC singleton for connection")
		return true
	}

	if RPCCLientSingleton != nil {
		return rpcEmergencyMode != true
	}

	// RPC Client is unset
	// Set up the cache
	log.Info("Setting new RPC connection!")

	connID := uuid.NewV4().String()

	// Length should fit into 1 byte. Protection if we decide change uuid in future.
	if len(connID) > 255 {
		panic("connID is too long")
	}

	if config.Global.SlaveOptions.UseSSL {
		clientCfg := &tls.Config{
			InsecureSkipVerify: config.Global.SlaveOptions.SSLInsecureSkipVerify,
		}

		RPCCLientSingleton = gorpc.NewTLSClient(r.Address, clientCfg)
	} else {
		RPCCLientSingleton = gorpc.NewTCPClient(r.Address)
	}

	if log.Level != logrus.DebugLevel {
		RPCCLientSingleton.LogError = gorpc.NilErrorLogger
	}

	RPCCLientSingleton.OnConnect = r.OnConnectFunc

	RPCCLientSingleton.Conns = config.Global.SlaveOptions.RPCPoolSize
	if config.Global.SlaveOptions.RPCPoolSize == 0 {
		RPCCLientSingleton.Conns = 20
	}

	RPCCLientSingleton.Dial = func(addr string) (conn io.ReadWriteCloser, err error) {
		dialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}

		configMu.Lock()
		useSSL := config.Global.SlaveOptions.UseSSL
		configMu.Unlock()

		if useSSL {
			cfg := &tls.Config{
				InsecureSkipVerify: config.Global.SlaveOptions.SSLInsecureSkipVerify,
			}

			conn, err = tls.DialWithDialer(dialer, "tcp", addr, cfg)
		} else {
			conn, err = dialer.Dial("tcp", addr)
		}

		if err != nil {
			emitRPCErrorEventKv(
				rpcCLientSingletonCall,
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
	RPCCLientSingleton.Start()
	d := getDispatcher()

	if RPCFuncClientSingleton == nil {
		RPCFuncClientSingleton = d.NewFuncClient(RPCCLientSingleton)
	}

	if !r.Login() {
		return false
	}

	if !r.SuppressRegister {
		r.Register()
		go r.checkDisconnect()
	}

	return true
}

func (r *RPCStorageHandler) OnConnectFunc(remoteAddr string, rwc io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	RPCCLientSingletonMu.Lock()
	defer RPCCLientSingletonMu.Unlock()

	RPCClientIsConnected = true
	return rwc, nil
}

func (r *RPCStorageHandler) Disconnect() bool {
	RPCClientIsConnected = false
	return true
}

func (r *RPCStorageHandler) hashKey(in string) string {
	if !r.HashKeys {
		// Not hashing? Return the raw key
		return in
	}
	return storage.HashStr(in)
}

func (r *RPCStorageHandler) fixKey(keyName string) string {
	setKeyName := r.KeyPrefix + r.hashKey(keyName)

	log.Debug("Input key was: ", setKeyName)

	return setKeyName
}

func (r *RPCStorageHandler) cleanKey(keyName string) string {
	setKeyName := strings.Replace(keyName, r.KeyPrefix, "", 1)
	return setKeyName
}

var rpcLoginMu sync.Mutex

func (r *RPCStorageHandler) ReAttemptLogin(err error) bool {
	rpcLoginMu.Lock()
	log.Warning("[RPC Store] Login failed, waiting 3s to re-attempt")

	if rpcLoadCount == 0 && !rpcEmergencyModeLoaded {
		log.Warning("[RPC Store] --> Detected cold start, attempting to load from cache")
		log.Warning("[RPC Store] ----> Found APIs... beginning emergency load")
		rpcEmergencyModeLoaded = true
		go doReload()
	}
	rpcLoginMu.Unlock()

	time.Sleep(time.Second * 3)
	if strings.Contains(err.Error(), "Cannot obtain response during timeout") {
		r.ReConnect()
		return false
	}
	return r.Login()
}

func (r *RPCStorageHandler) GroupLogin() bool {
	groupLoginData := GroupLoginRequest{
		UserKey: r.UserKey,
		GroupID: config.Global.SlaveOptions.GroupID,
	}
	ok, err := RPCFuncClientSingleton.CallTimeout("LoginWithGroup", groupLoginData, GlobalRPCCallTimeout)
	if err != nil {
		log.Error("RPC Login failed: ", err)
		emitRPCErrorEventKv(
			rpcFuncClientSingletonCall,
			"LoginWithGroup",
			err,
			map[string]string{
				"GroupID": groupLoginData.GroupID,
			},
		)
		rpcEmergencyMode = true
		go r.ReAttemptLogin(err)
		return false
	}

	if ok == false {
		log.Error("RPC Login incorrect")
		rpcEmergencyMode = true
		go r.ReAttemptLogin(errors.New("Login incorrect"))
		return false
	}
	log.Debug("[RPC Store] Group Login complete")
	rpcLoadCount++

	// Recovery
	if rpcEmergencyMode {
		rpcEmergencyMode = false
		rpcEmergencyModeLoaded = false
		reloadURLStructure(nil)
	}

	return true
}

func (r *RPCStorageHandler) Login() bool {
	log.Debug("[RPC Store] Login initiated")

	if len(r.UserKey) == 0 {
		log.Fatal("No API Key set!")
	}

	// If we have a group ID, lets login as a group
	if config.Global.SlaveOptions.GroupID != "" {
		return r.GroupLogin()
	}

	ok, err := RPCFuncClientSingleton.CallTimeout("Login", r.UserKey, GlobalRPCCallTimeout)
	if err != nil {
		log.Error("RPC Login failed: ", err)
		emitRPCErrorEvent(rpcFuncClientSingletonCall, "Login", err)
		rpcEmergencyMode = true
		go r.ReAttemptLogin(err)
		return false
	}

	if ok == false {
		log.Error("RPC Login incorrect")
		rpcEmergencyMode = true
		go r.ReAttemptLogin(errors.New("Login incorrect"))
		return false
	}
	log.Debug("[RPC Store] Login complete")
	rpcLoadCount++

	if rpcEmergencyMode {
		rpcEmergencyMode = false
		rpcEmergencyModeLoaded = false
		reloadURLStructure(nil)
	}

	return true
}

// GetKey will retrieve a key from the database
func (r *RPCStorageHandler) GetKey(keyName string) (string, error) {
	start := time.Now() // get current time
	log.Debug("[STORE] Getting WAS: ", keyName)
	log.Debug("[STORE] Getting: ", r.fixKey(keyName))

	// Check the cache first
	if config.Global.SlaveOptions.EnableRPCCache {
		log.Debug("Using cache for: ", keyName)
		cachedVal, found := RPCGlobalCache.Get(r.fixKey(keyName))
		log.Debug("--> Found? ", found)
		if found {
			elapsed := time.Since(start)
			log.Debug("GetKey took ", elapsed)
			log.Debug(cachedVal.(string))
			return cachedVal.(string), nil
		}
	}

	// Not cached
	value, err := RPCFuncClientSingleton.CallTimeout("GetKey", r.fixKey(keyName), GlobalRPCCallTimeout)
	if err != nil {
		emitRPCErrorEventKv(
			rpcFuncClientSingletonCall,
			"GetKey",
			err,
			map[string]string{
				"keyName":      keyName,
				"fixedKeyName": r.fixKey(keyName),
			},
		)
		if r.IsAccessError(err) {
			if r.Login() {
				return r.GetKey(keyName)
			}
		}

		log.Debug("Error trying to get value:", err)
		return "", storage.ErrKeyNotFound
	}
	elapsed := time.Since(start)
	log.Debug("GetKey took ", elapsed)

	if config.Global.SlaveOptions.EnableRPCCache {
		// Cache it
		RPCGlobalCache.Set(r.fixKey(keyName), value, cache.DefaultExpiration)
	}

	return value.(string), nil
}

func (r *RPCStorageHandler) GetRawKey(keyName string) (string, error) {
	log.Error("Not Implemented!")
	return "", nil
}

func (r *RPCStorageHandler) GetExp(keyName string) (int64, error) {
	log.Debug("GetExp called")
	value, err := RPCFuncClientSingleton.CallTimeout("GetExp", r.fixKey(keyName), GlobalRPCCallTimeout)
	if err != nil {
		emitRPCErrorEventKv(
			rpcFuncClientSingletonCall,
			"GetExp",
			err,
			map[string]string{
				"keyName":      keyName,
				"fixedKeyName": r.fixKey(keyName),
			},
		)
		if r.IsAccessError(err) {
			if r.Login() {
				return r.GetExp(keyName)
			}
		}
		log.Error("Error trying to get TTL: ", err)
		return 0, storage.ErrKeyNotFound
	}
	return value.(int64), nil
}

func (r *RPCStorageHandler) SetExp(keyName string, timeout int64) error {
	log.Error("SetExp Not Implemented")
	return nil
}

// SetKey will create (or update) a key value in the store
func (r *RPCStorageHandler) SetKey(keyName, session string, timeout int64) error {
	start := time.Now() // get current time
	ibd := InboundData{
		KeyName:      r.fixKey(keyName),
		SessionState: session,
		Timeout:      timeout,
	}

	_, err := RPCFuncClientSingleton.CallTimeout("SetKey", ibd, GlobalRPCCallTimeout)
	if err != nil {
		emitRPCErrorEventKv(
			rpcFuncClientSingletonCall,
			"SetKey",
			err,
			map[string]string{
				"keyName":      keyName,
				"fixedKeyName": ibd.KeyName,
			},
		)

		if r.IsAccessError(err) {
			if r.Login() {
				return r.SetKey(keyName, session, timeout)
			}
		}

		log.Debug("Error trying to set value:", err)
		return err
	}

	elapsed := time.Since(start)
	log.Debug("SetKey took ", elapsed)
	return nil

}

func (r *RPCStorageHandler) SetRawKey(keyName, session string, timeout int64) error {
	return nil
}

// Decrement will decrement a key in redis
func (r *RPCStorageHandler) Decrement(keyName string) {
	log.Warning("Decrement called")
	_, err := RPCFuncClientSingleton.CallTimeout("Decrement", keyName, GlobalRPCCallTimeout)
	if err != nil {
		emitRPCErrorEventKv(
			rpcFuncClientSingletonCall,
			"Decrement",
			err,
			map[string]string{
				"keyName": keyName,
			},
		)
	}
	if r.IsAccessError(err) {
		if r.Login() {
			r.Decrement(keyName)
			return
		}
	}
}

// IncrementWithExpire will increment a key in redis
func (r *RPCStorageHandler) IncrememntWithExpire(keyName string, expire int64) int64 {

	ibd := InboundData{
		KeyName: keyName,
		Expire:  expire,
	}

	val, err := RPCFuncClientSingleton.CallTimeout("IncrememntWithExpire", ibd, GlobalRPCCallTimeout)
	if err != nil {
		emitRPCErrorEventKv(
			rpcFuncClientSingletonCall,
			"IncrememntWithExpire",
			err,
			map[string]string{
				"keyName": keyName,
			},
		)
	}
	if r.IsAccessError(err) {
		if r.Login() {
			return r.IncrememntWithExpire(keyName, expire)
		}
	}

	if val == nil {
		log.Warning("RPC increment returned nil value, returning 0")
		return 0
	}

	return val.(int64)

}

// GetKeys will return all keys according to the filter (filter is a prefix - e.g. tyk.keys.*)
func (r *RPCStorageHandler) GetKeys(filter string) []string {
	log.Error("GetKeys Not Implemented")
	return nil
}

// GetKeysAndValuesWithFilter will return all keys and their values with a filter
func (r *RPCStorageHandler) GetKeysAndValuesWithFilter(filter string) map[string]string {

	searchStr := r.KeyPrefix + r.hashKey(filter) + "*"
	log.Debug("[STORE] Getting list by: ", searchStr)

	kvPair, err := RPCFuncClientSingleton.CallTimeout("GetKeysAndValuesWithFilter", searchStr, GlobalRPCCallTimeout)
	if err != nil {
		emitRPCErrorEventKv(
			rpcFuncClientSingletonCall,
			"GetKeysAndValuesWithFilter",
			err,
			map[string]string{
				"searchStr": searchStr,
			},
		)

		if r.IsAccessError(err) {
			if r.Login() {
				return r.GetKeysAndValuesWithFilter(filter)
			}
		}

		return nil
	}

	returnValues := make(map[string]string)

	for i, v := range kvPair.(*KeysValuesPair).Keys {
		returnValues[r.cleanKey(v)] = kvPair.(*KeysValuesPair).Values[i]
	}

	return returnValues
}

// GetKeysAndValues will return all keys and their values - not to be used lightly
func (r *RPCStorageHandler) GetKeysAndValues() map[string]string {

	searchStr := r.KeyPrefix + "*"

	kvPair, err := RPCFuncClientSingleton.CallTimeout("GetKeysAndValues", searchStr, GlobalRPCCallTimeout)
	if err != nil {
		emitRPCErrorEvent(rpcFuncClientSingletonCall, "GetKeysAndValues", err)

		if r.IsAccessError(err) {
			if r.Login() {
				return r.GetKeysAndValues()
			}
		}

		return nil
	}

	returnValues := make(map[string]string)
	for i, v := range kvPair.(*KeysValuesPair).Keys {
		returnValues[r.cleanKey(v)] = kvPair.(*KeysValuesPair).Values[i]
	}

	return returnValues

}

// DeleteKey will remove a key from the database
func (r *RPCStorageHandler) DeleteKey(keyName string) bool {

	log.Debug("DEL Key was: ", keyName)
	log.Debug("DEL Key became: ", r.fixKey(keyName))
	ok, err := RPCFuncClientSingleton.CallTimeout("DeleteKey", r.fixKey(keyName), GlobalRPCCallTimeout)
	if err != nil {
		emitRPCErrorEventKv(
			rpcFuncClientSingletonCall,
			"DeleteKey",
			err,
			map[string]string{
				"keyName":      keyName,
				"fixedKeyName": r.fixKey(keyName),
			},
		)

		if r.IsAccessError(err) {
			if r.Login() {
				return r.DeleteKey(keyName)
			}
		}
	}

	return ok == true
}

// DeleteKey will remove a key from the database without prefixing, assumes user knows what they are doing
func (r *RPCStorageHandler) DeleteRawKey(keyName string) bool {
	ok, err := RPCFuncClientSingleton.CallTimeout("DeleteRawKey", keyName, GlobalRPCCallTimeout)
	if err != nil {
		emitRPCErrorEventKv(
			rpcFuncClientSingletonCall,
			"DeleteRawKey",
			err,
			map[string]string{
				"keyName": keyName,
			},
		)

		if r.IsAccessError(err) {
			if r.Login() {
				return r.DeleteRawKey(keyName)
			}
		}
	}

	return ok == true
}

// DeleteKeys will remove a group of keys in bulk
func (r *RPCStorageHandler) DeleteKeys(keys []string) bool {
	if len(keys) > 0 {
		asInterface := make([]string, len(keys))
		for i, v := range keys {
			asInterface[i] = r.fixKey(v)
		}

		log.Debug("Deleting: ", asInterface)
		ok, err := RPCFuncClientSingleton.CallTimeout("DeleteKeys", asInterface, GlobalRPCCallTimeout)
		if err != nil {
			emitRPCErrorEventKv(
				rpcFuncClientSingletonCall,
				"DeleteKeys",
				err,
				map[string]string{
					"keys":        strings.Join(keys, ","),
					"asInterface": strings.Join(asInterface, ","),
				},
			)

			if r.IsAccessError(err) {
				if r.Login() {
					return r.DeleteKeys(keys)
				}
			}
		}

		return ok == true
	}
	log.Debug("RPCStorageHandler called DEL - Nothing to delete")
	return true
}

// StartPubSubHandler will listen for a signal and run the callback with the message
func (r *RPCStorageHandler) StartPubSubHandler(channel string, callback func(redis.Message)) error {
	log.Warning("NO PUBSUB DEFINED")
	return nil
}

func (r *RPCStorageHandler) Publish(channel, message string) error {
	log.Warning("NO PUBSUB DEFINED")
	return nil
}

func (r *RPCStorageHandler) GetAndDeleteSet(keyName string) []interface{} {
	log.Error("GetAndDeleteSet Not implemented, please disable your purger")
	return nil
}

func (r *RPCStorageHandler) AppendToSet(keyName, value string) {
	ibd := InboundData{
		KeyName: keyName,
		Value:   value,
	}

	_, err := RPCFuncClientSingleton.CallTimeout("AppendToSet", ibd, GlobalRPCCallTimeout)
	if err != nil {
		emitRPCErrorEventKv(
			rpcFuncClientSingletonCall,
			"AppendToSet",
			err,
			map[string]string{
				"keyName": keyName,
			},
		)
	}
	if r.IsAccessError(err) {
		if r.Login() {
			r.AppendToSet(keyName, value)
		}
	}
}

// SetScrollingWindow is used in the rate limiter to handle rate limits fairly.
func (r *RPCStorageHandler) SetRollingWindow(keyName string, per int64, val string, pipeline bool) (int, []interface{}) {
	start := time.Now() // get current time
	ibd := InboundData{
		KeyName: keyName,
		Per:     per,
		Expire:  -1,
	}

	intVal, err := RPCFuncClientSingleton.CallTimeout("SetRollingWindow", ibd, GlobalRPCCallTimeout)
	if err != nil {
		emitRPCErrorEventKv(
			rpcFuncClientSingletonCall,
			"SetRollingWindow",
			err,
			map[string]string{
				"keyName": keyName,
				"per":     strconv.Itoa(int(per)),
			},
		)

		if r.IsAccessError(err) {
			if r.Login() {
				return r.SetRollingWindow(keyName, per, val, false)
			}
		}
	}

	elapsed := time.Since(start)
	log.Debug("SetRollingWindow took ", elapsed)

	if intVal == nil {
		log.Warning("RPC Handler: SetRollingWindow() returned nil, returning 0")
		return 0, nil
	}

	return intVal.(int), nil

}

func (r RPCStorageHandler) GetSet(keyName string) (map[string]string, error) {
	log.Error("Not implemented")
	return nil, nil
}

func (r RPCStorageHandler) AddToSet(keyName, value string) {
	log.Error("Not implemented")
}

func (r RPCStorageHandler) RemoveFromSet(keyName, value string) {
	log.Error("Not implemented")
}

func (r RPCStorageHandler) IsAccessError(err error) bool {
	if err != nil {
		return err.Error() == "Access Denied"
	}
	return false
}

// GetAPIDefinitions will pull API definitions from the RPC server
func (r *RPCStorageHandler) GetApiDefinitions(orgId string, tags []string) string {
	dr := DefRequest{
		OrgId: orgId,
		Tags:  tags,
	}

	defString, err := RPCFuncClientSingleton.CallTimeout("GetApiDefinitions", dr, GlobalRPCCallTimeout)
	if err != nil {
		emitRPCErrorEventKv(
			rpcFuncClientSingletonCall,
			"GetApiDefinitions",
			err,
			map[string]string{
				"orgId": orgId,
				"tags":  strings.Join(tags, ","),
			},
		)

		if r.IsAccessError(err) {
			if r.Login() {
				return r.GetApiDefinitions(orgId, tags)
			}
		}

		return ""
	}
	log.Debug("API Definitions retrieved")

	if defString == nil {
		log.Warning("RPC Handler: GetApiDefinitions() returned nil, returning empty string")
		return ""
	}
	return defString.(string)
}

// GetPolicies will pull Policies from the RPC server
func (r *RPCStorageHandler) GetPolicies(orgId string) string {
	defString, err := RPCFuncClientSingleton.CallTimeout("GetPolicies", orgId, GlobalRPCCallTimeout)
	if err != nil {
		emitRPCErrorEventKv(
			rpcFuncClientSingletonCall,
			"GetPolicies",
			err,
			map[string]string{
				"orgId": orgId,
			},
		)

		if r.IsAccessError(err) {
			if r.Login() {
				return r.GetPolicies(orgId)
			}
		}

		return ""
	}

	if defString != nil {
		return defString.(string)
	}
	return ""
}

// CheckForReload will start a long poll
func (r *RPCStorageHandler) CheckForReload(orgId string) {
	log.Debug("[RPC STORE] Check Reload called...")
	reload, err := RPCFuncClientSingleton.CallTimeout("CheckReload", orgId, GlobalRPCPingTimeout)
	if err != nil {
		emitRPCErrorEventKv(
			rpcFuncClientSingletonCall,
			"CheckReload",
			err,
			map[string]string{
				"orgId": orgId,
			},
		)
		if r.IsAccessError(err) {
			log.Warning("[RPC STORE] CheckReload: Not logged in")
			if r.Login() {
				r.CheckForReload(orgId)
			}
		} else if !strings.Contains(err.Error(), "Cannot obtain response during") {
			log.Warning("[RPC STORE] RPC Reload Checker encountered unexpected error: ", err)
		}
	} else if reload == true {
		// Do the reload!
		log.Warning("[RPC STORE] Received Reload instruction!")
		go func() {
			MainNotifier.Notify(Notification{Command: NoticeGroupReload})
		}()
	}
}

func (r *RPCStorageHandler) StartRPCLoopCheck(orgId string) {
	if config.Global.SlaveOptions.DisableKeySpaceSync {
		return
	}

	log.Info("[RPC] Starting keyspace poller")

	for {
		r.CheckForKeyspaceChanges(orgId)
		time.Sleep(10 * time.Second)
	}
}

func (r *RPCStorageHandler) StartRPCKeepaliveWatcher() {
	log.WithFields(logrus.Fields{
		"prefix": "RPC Conn Mgr",
	}).Info("[RPC Conn Mgr] Starting keepalive watcher...")
	for {

		if err := r.SetKey("0000", "0000", 10); err != nil {
			if r.IsAccessError(err) {
				if r.Login() {
					continue
				}
			}

			if strings.Contains(err.Error(), "Cannot obtain response during timeout") {
				log.WithFields(logrus.Fields{
					"prefix": "RPC Conn Mgr",
				}).Info("Can't connect to RPC layer")
				continue
			}
		}

		log.WithFields(logrus.Fields{
			"prefix": "RPC Conn Mgr",
		}).Info("RPC is alive")

		time.Sleep(10 * time.Second)
	}
}

// CheckForKeyspaceChanges will poll for keysace changes
func (r *RPCStorageHandler) CheckForKeyspaceChanges(orgId string) {
	log.Debug("Checking for keyspace changes...")

	var keys interface{}
	var err error
	var funcName string
	var req interface{}

	reqData := map[string]string{}
	if config.Global.SlaveOptions.GroupID == "" {
		funcName = "GetKeySpaceUpdate"
		req = orgId
		reqData["orgId"] = orgId
	} else {
		funcName = "GetGroupKeySpaceUpdate"
		req = GroupKeySpaceRequest{
			OrgID:   orgId,
			GroupID: config.Global.SlaveOptions.GroupID,
		}
		reqData["orgId"] = orgId
		reqData["GroupID"] = config.Global.SlaveOptions.GroupID
	}

	keys, err = RPCFuncClientSingleton.CallTimeout(funcName, req, GlobalRPCCallTimeout)
	if err != nil {
		emitRPCErrorEventKv(
			rpcFuncClientSingletonCall,
			funcName,
			err,
			reqData,
		)
		if r.IsAccessError(err) {
			if r.Login() {
				r.CheckForKeyspaceChanges(orgId)
			}
		}
		log.Warning("Keysapce warning: ", err)
		return
	}

	if keys == nil {
		log.Info("Keys returned nil object, skipping check")
		return
	}

	if len(keys.([]string)) > 0 {
		log.Info("Keyspace changes detected, updating local cache")
		go r.ProcessKeySpaceChanges(keys.([]string))
	}
}

func (r *RPCStorageHandler) ProcessKeySpaceChanges(keys []string) {
	for _, key := range keys {
		splitKeys := strings.Split(key, ":")
		if len(splitKeys) > 1 {
			if splitKeys[1] == "hashed" {
				log.Info("--> removing cached (hashed) key: ", splitKeys[0])
				handleDeleteHashedKey(splitKeys[0], "")
			}
		} else {
			log.Info("--> removing cached key: ", key)
			handleDeleteKey(key, "-1")
		}

	}
}

func (r *RPCStorageHandler) DeleteScanMatch(pattern string) bool {
	log.Error("Not implemented")
	return false
}

func (r *RPCStorageHandler) GetKeyPrefix() string {
	log.Error("Not implemented")
	return ""
}

func (r *RPCStorageHandler) AddToSortedSet(keyName, value string, score float64) {
	log.Error("Not implemented")
}

func (r *RPCStorageHandler) GetSortedSetRange(keyName, scoreFrom, scoreTo string) ([]string, []float64, error) {
	log.Error("Not implemented")
	return nil, nil, nil
}

func (r *RPCStorageHandler) RemoveSortedSetRange(keyName, scoreFrom, scoreTo string) error {
	log.Error("Not implemented")
	return nil
}

func getDispatcher() *gorpc.Dispatcher {
	dispatch := gorpc.NewDispatcher()

	dispatch.AddFunc("Login", func(clientAddr, userKey string) bool {
		return false
	})

	dispatch.AddFunc("LoginWithGroup", func(clientAddr string, groupData *GroupLoginRequest) bool {
		return false
	})

	dispatch.AddFunc("GetKey", func(keyName string) (string, error) {
		return "", nil
	})

	dispatch.AddFunc("SetKey", func(ibd *InboundData) error {
		return nil
	})

	dispatch.AddFunc("GetExp", func(keyName string) (int64, error) {
		return 0, nil
	})

	dispatch.AddFunc("GetKeys", func(keyName string) ([]string, error) {
		return nil, nil
	})

	dispatch.AddFunc("DeleteKey", func(keyName string) (bool, error) {
		return true, nil
	})

	dispatch.AddFunc("DeleteRawKey", func(keyName string) (bool, error) {
		return true, nil
	})

	dispatch.AddFunc("GetKeysAndValues", func(searchString string) (*KeysValuesPair, error) {
		return nil, nil
	})

	dispatch.AddFunc("GetKeysAndValuesWithFilter", func(searchString string) (*KeysValuesPair, error) {
		return nil, nil
	})

	dispatch.AddFunc("DeleteKeys", func(keys []string) (bool, error) {
		return true, nil
	})

	dispatch.AddFunc("Decrement", func(keyName string) error {
		return nil
	})

	dispatch.AddFunc("IncrememntWithExpire", func(ibd *InboundData) (int64, error) {
		return 0, nil
	})

	dispatch.AddFunc("AppendToSet", func(ibd *InboundData) error {
		return nil
	})

	dispatch.AddFunc("SetRollingWindow", func(ibd *InboundData) (int, error) {
		return 0, nil
	})

	dispatch.AddFunc("GetApiDefinitions", func(dr *DefRequest) (string, error) {
		return "", nil
	})

	dispatch.AddFunc("GetPolicies", func(orgId string) (string, error) {
		return "", nil
	})

	dispatch.AddFunc("PurgeAnalyticsData", func(data string) error {
		return nil
	})

	dispatch.AddFunc("CheckReload", func(clientAddr, orgId string) (bool, error) {
		return false, nil
	})

	dispatch.AddFunc("GetKeySpaceUpdate", func(clientAddr, orgId string) ([]string, error) {
		return nil, nil
	})

	dispatch.AddFunc("GetGroupKeySpaceUpdate", func(clientAddr string, groupData *GroupKeySpaceRequest) ([]string, error) {
		return nil, nil
	})

	dispatch.AddFunc("Ping", func() bool {
		return false
	})

	return dispatch

}
