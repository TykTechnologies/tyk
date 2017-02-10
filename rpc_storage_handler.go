package main

import (
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/TykTechnologies/logrus"
	"github.com/garyburd/redigo/redis"
	"github.com/lonelycode/go-uuid/uuid"
	"github.com/lonelycode/gorpc"
	"github.com/pmylund/go-cache"
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
	// RPC_LoadCount is a counter to check if this is a cold boot
	RPC_LoadCount           int
	RPC_EmergencyMode       bool
	RPC_EmergencyModeLoaded bool

	GlobalRPCCallTimeout time.Duration
	GlobalRPCPingTimeout time.Duration
)

// ------------------- CLOUD STORAGE MANAGER -------------------------------

var RPCCLientRWMutex = sync.RWMutex{}
var RPCClients = map[string]chan int{}

func RPCKeepAliveCheck(r *RPCStorageHandler) {
	// Only run when connected
	if RPCClientIsConnected {
		// Make sure the auth back end is still alive
		c1 := make(chan string, 1)

		go func() {
			log.Debug("Getting keyspace check test key")
			r.GetKey("0000")
			log.Debug("--> done")
			c1 <- "1"
			close(c1)
		}()

		ctd := false
		select {
		case res := <-c1:
			log.Debug("RPC Still alive: ", res)
			ctd = true
		case <-time.After(time.Second * 10):
			log.WithFields(logrus.Fields{
				"prefix": "RPC Conn Mgr",
			}).Warning("Handler seems to have disconnected, attempting reconnect")
			r.ReConnect()
		}

		if ctd {
			// Don't run too quickly, pulse every 10 secs
			time.Sleep(time.Second * 10)
		}
	}
}

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
	r.ID = uuid.NewUUID().String()
	myChan := make(chan int)
	RPCCLientRWMutex.Lock()
	RPCClients[r.ID] = myChan
	RPCCLientRWMutex.Unlock()
	r.killChan = myChan
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
var RPCFuncClientSingleton *gorpc.DispatcherClient
var RPCGlobalCache = cache.New(30*time.Second, 15*time.Second)
var RPCClientIsConnected bool

// Connect will establish a connection to the DB
func (r *RPCStorageHandler) Connect() bool {

	if RPCClientIsConnected {
		log.Debug("Using RPC singleton for connection")
		return true
	}

	// RPC Client is unset
	// Set up the cache
	log.Info("Setting new RPC connection!")
	RPCCLientSingleton = gorpc.NewTCPClient(r.Address)

	if log.Level != logrus.DebugLevel {
		gorpc.SetErrorLogger(gorpc.NilErrorLogger)
	}

	RPCCLientSingleton.OnConnect = r.OnConnectFunc
	RPCCLientSingleton.Conns = 50
	RPCCLientSingleton.Start()
	d := GetDispatcher()

	if RPCFuncClientSingleton == nil {
		RPCFuncClientSingleton = d.NewFuncClient(RPCCLientSingleton)
	}

	r.Login()

	if !r.SuppressRegister {
		r.Register()
		go r.checkDisconnect()
	}

	return true
}

func (r *RPCStorageHandler) OnConnectFunc(remoteAddr string, rwc io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	RPCClientIsConnected = true
	return rwc, nil
}

func (r *RPCStorageHandler) Disconnect() bool {
	if RPCClientIsConnected {
		RPCClientIsConnected = false
		RPCCLientRWMutex.Lock()
		delete(RPCClients, r.ID)
		RPCCLientRWMutex.Unlock()
	}
	return true
}

func (r *RPCStorageHandler) hashKey(in string) string {
	if !r.HashKeys {
		// Not hashing? Return the raw key
		return in
	}
	return doHash(in)
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

func (r *RPCStorageHandler) ReAttemptLogin(err error) {
	log.Warning("[RPC Store] Login failed, waiting 3s to re-attempt")

	if RPC_LoadCount == 0 {
		if !RPC_EmergencyModeLoaded {
			log.Warning("[RPC Store] --> Detected cold start, attempting to load from cache")
			APIlist := LoadDefinitionsFromRPCBackup()
			log.Warning("[RPC Store] --> Done")
			if APIlist != nil {
				RPC_EmergencyMode = true
				log.Warning("[RPC Store] ----> Found APIs... beginning emergency load")
				doLoadWithBackup(APIlist)
			}

			//LoadPoliciesFromRPCBackup()
		}
	}

	time.Sleep(time.Second * 3)
	if strings.Contains(err.Error(), "Cannot obtain response during timeout") {
		r.ReConnect()
		return
	}
	r.Login()
}

func (r *RPCStorageHandler) GroupLogin() {
	groupLoginData := GroupLoginRequest{
		UserKey: r.UserKey,
		GroupID: config.SlaveOptions.GroupID,
	}
	ok, err := RPCFuncClientSingleton.CallTimeout("LoginWithGroup", groupLoginData, GlobalRPCCallTimeout)
	if err != nil {
		log.Error("RPC Login failed: ", err)
		r.ReAttemptLogin(err)
		return
	}

	if !ok.(bool) {
		log.Error("RPC Login incorrect")
		r.ReAttemptLogin(errors.New("Login incorrect"))
		return
	}
	log.Debug("[RPC Store] Group Login complete")
	RPC_LoadCount++
}

func (r *RPCStorageHandler) Login() {
	log.Debug("[RPC Store] Login initiated")

	if len(r.UserKey) == 0 {
		log.Fatal("No API Key set!")
	}

	// If we have a group ID, lets login as a group
	if config.SlaveOptions.GroupID != "" {
		r.GroupLogin()
		return
	}

	ok, err := RPCFuncClientSingleton.CallTimeout("Login", r.UserKey, GlobalRPCCallTimeout)
	if err != nil {
		log.Error("RPC Login failed: ", err)
		r.ReAttemptLogin(err)
		return
	}

	if !ok.(bool) {
		log.Error("RPC Login incorrect")
		r.ReAttemptLogin(errors.New("Login incorrect"))
		return
	}
	log.Debug("[RPC Store] Login complete")
	RPC_LoadCount++
}

// GetKey will retrieve a key from the database
func (r *RPCStorageHandler) GetKey(keyName string) (string, error) {
	start := time.Now() // get current time
	log.Debug("[STORE] Getting WAS: ", keyName)
	log.Debug("[STORE] Getting: ", r.fixKey(keyName))

	// Check the cache first
	if config.SlaveOptions.EnableRPCCache {
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
		if r.IsAccessError(err) {
			r.Login()
			return r.GetKey(keyName)
		}

		log.Debug("Error trying to get value:", err)
		return "", KeyError{}
	}
	elapsed := time.Since(start)
	log.Debug("GetKey took ", elapsed)

	if config.SlaveOptions.EnableRPCCache {
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
		if r.IsAccessError(err) {
			r.Login()
			return r.GetExp(keyName)
		}
		log.Error("Error trying to get TTL: ", err)
	} else {
		return value.(int64), nil
	}

	return 0, KeyError{}
}

// SetKey will create (or update) a key value in the store
func (r *RPCStorageHandler) SetKey(keyName string, sessionState string, timeout int64) error {
	start := time.Now() // get current time
	ibd := InboundData{
		KeyName:      r.fixKey(keyName),
		SessionState: sessionState,
		Timeout:      timeout,
	}

	_, err := RPCFuncClientSingleton.CallTimeout("SetKey", ibd, GlobalRPCCallTimeout)

	if r.IsAccessError(err) {
		r.Login()
		return r.SetKey(keyName, sessionState, timeout)
	}

	elapsed := time.Since(start)
	log.Debug("SetKey took ", elapsed)
	return nil

}

func (r *RPCStorageHandler) SetRawKey(keyName string, sessionState string, timeout int64) error {
	return nil
}

// Decrement will decrement a key in redis
func (r *RPCStorageHandler) Decrement(keyName string) {
	log.Warning("Decrement called")
	_, err := RPCFuncClientSingleton.CallTimeout("Decrement", keyName, GlobalRPCCallTimeout)
	if r.IsAccessError(err) {
		r.Login()
		r.Decrement(keyName)
		return
	}
}

// IncrementWithExpire will increment a key in redis
func (r *RPCStorageHandler) IncrememntWithExpire(keyName string, expire int64) int64 {

	ibd := InboundData{
		KeyName: keyName,
		Expire:  expire,
	}

	val, err := RPCFuncClientSingleton.CallTimeout("IncrememntWithExpire", ibd, GlobalRPCCallTimeout)

	if r.IsAccessError(err) {
		r.Login()
		return r.IncrememntWithExpire(keyName, expire)
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

	return []string{}
}

// GetKeysAndValuesWithFilter will return all keys and their values with a filter
func (r *RPCStorageHandler) GetKeysAndValuesWithFilter(filter string) map[string]string {

	searchStr := r.KeyPrefix + r.hashKey(filter) + "*"
	log.Debug("[STORE] Getting list by: ", searchStr)

	kvPair, err := RPCFuncClientSingleton.CallTimeout("GetKeysAndValuesWithFilter", searchStr, GlobalRPCCallTimeout)

	if r.IsAccessError(err) {
		r.Login()
		return r.GetKeysAndValuesWithFilter(filter)
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

	if r.IsAccessError(err) {
		r.Login()
		return r.GetKeysAndValues()
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

	if r.IsAccessError(err) {
		r.Login()
		return r.DeleteKey(keyName)
	}

	if ok == nil {
		return false
	}
	return ok.(bool)
}

// DeleteKey will remove a key from the database without prefixing, assumes user knows what they are doing
func (r *RPCStorageHandler) DeleteRawKey(keyName string) bool {
	ok, err := RPCFuncClientSingleton.CallTimeout("DeleteRawKey", keyName, GlobalRPCCallTimeout)

	if r.IsAccessError(err) {
		r.Login()
		return r.DeleteRawKey(keyName)
	}

	if ok == nil {
		return false
	}
	return ok.(bool)
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

		if r.IsAccessError(err) {
			r.Login()
			return r.DeleteKeys(keys)
		}

		if ok == nil {
			return false
		}

		return ok.(bool)
	}
	log.Debug("RPCStorageHandler called DEL - Nothing to delete")
	return true
}

// DeleteKeys will remove a group of keys in bulk without a prefix handler
func (r *RPCStorageHandler) DeleteRawKeys(keys []string, prefix string) bool {
	log.Error("DeleteRawKeys Not Implemented")
	return false
}

// StartPubSubHandler will listen for a signal and run the callback with the message
func (r *RPCStorageHandler) StartPubSubHandler(channel string, callback func(redis.Message)) error {
	log.Warning("NO PUBSUB DEFINED")
	return nil
}

func (r *RPCStorageHandler) Publish(channel string, message string) error {
	log.Warning("NO PUBSUB DEFINED")
	return nil
}

func (r *RPCStorageHandler) GetAndDeleteSet(keyName string) []interface{} {
	log.Error("GetAndDeleteSet Not implemented, please disable your purger")

	return []interface{}{}
}

func (r *RPCStorageHandler) AppendToSet(keyName string, value string) {

	ibd := InboundData{
		KeyName: keyName,
		Value:   value,
	}

	_, err := RPCFuncClientSingleton.CallTimeout("AppendToSet", ibd, GlobalRPCCallTimeout)
	if r.IsAccessError(err) {
		r.Login()
		r.AppendToSet(keyName, value)
		return
	}

}

// SetScrollingWindow is used in the rate limiter to handle rate limits fairly.
func (r *RPCStorageHandler) SetRollingWindow(keyName string, per int64, val string) (int, []interface{}) {
	start := time.Now() // get current time
	ibd := InboundData{
		KeyName: keyName,
		Per:     per,
		Expire:  -1,
	}

	intVal, err := RPCFuncClientSingleton.CallTimeout("SetRollingWindow", ibd, GlobalRPCCallTimeout)
	if r.IsAccessError(err) {
		r.Login()
		return r.SetRollingWindow(keyName, per, val)
	}

	elapsed := time.Since(start)
	log.Debug("SetRollingWindow took ", elapsed)

	if intVal == nil {
		log.Warning("RPC Handler: SetRollingWindow() returned nil, returning 0")
		return 0, []interface{}{}
	}

	return intVal.(int), []interface{}{}

}

func (r *RPCStorageHandler) SetRollingWindowPipeline(keyName string, per int64, val string) (int, []interface{}) {
	return r.SetRollingWindow(keyName, per, val)
}

func (r RPCStorageHandler) GetSet(keyName string) (map[string]string, error) {
	log.Error("Not implemented")
	return map[string]string{}, nil
}

func (r RPCStorageHandler) AddToSet(keyName string, value string) {
	log.Error("Not implemented")
}

func (r RPCStorageHandler) RemoveFromSet(keyName string, value string) {
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
		if r.IsAccessError(err) {
			r.Login()
			return r.GetApiDefinitions(orgId, tags)
		}
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
		if r.IsAccessError(err) {
			r.Login()
			return r.GetPolicies(orgId)
		}
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
		if r.IsAccessError(err) {
			log.Warning("[RPC STORE] CheckReload: Not logged in")
			r.ReConnect()
		} else if !strings.Contains(err.Error(), "Cannot obtain response during") {
			log.Warning("[RPC STORE] RPC Reload Checker encountered unexpected error: ", err)
			r.ReConnect()
		}
	} else {
		log.Debug("[RPC STORE] CheckReload: Received response")
		if reload.(bool) {
			// Do the reload!
			log.Warning("[RPC STORE] Received Reload instruction!")
			go signalGroupReload()
			//go ReloadURLStructure()
		}
	}

}

func (r *RPCStorageHandler) StartRPCLoopCheck(orgId string) {
	if config.SlaveOptions.DisableKeySpaceSync {
		return
	}

	log.Info("[RPC] Starting keyspace poller")

	for {
		r.CheckForKeyspaceChanges(orgId)
		time.Sleep(10 * time.Second)
	}
}

// CheckForKeyspaceChanges will poll for keysace changes
func (r *RPCStorageHandler) CheckForKeyspaceChanges(orgId string) {
	log.Debug("Checking for keyspace changes...")

	var keys interface{}
	var err error

	if config.SlaveOptions.GroupID == "" {
		keys, err = RPCFuncClientSingleton.CallTimeout("GetKeySpaceUpdate", orgId, GlobalRPCCallTimeout)
	} else {

		grpReq := GroupKeySpaceRequest{
			OrgID:   orgId,
			GroupID: config.SlaveOptions.GroupID,
		}
		keys, err = RPCFuncClientSingleton.CallTimeout("GetGroupKeySpaceUpdate", grpReq, GlobalRPCCallTimeout)
	}

	if err != nil {
		if r.IsAccessError(err) {
			r.Login()
			r.CheckForKeyspaceChanges(orgId)
		}
		log.Warning("Keysapce warning: ", err)
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

func GetDispatcher() *gorpc.Dispatcher {
	Dispatch := gorpc.NewDispatcher()

	Dispatch.AddFunc("Login", func(clientAddr string, userKey string) bool {
		return false
	})

	Dispatch.AddFunc("LoginWithGroup", func(clientAddr string, groupData *GroupLoginRequest) bool {
		return false
	})

	Dispatch.AddFunc("GetKey", func(keyName string) (string, error) {
		return "", nil
	})

	Dispatch.AddFunc("SetKey", func(ibd *InboundData) error {
		return nil
	})

	Dispatch.AddFunc("GetExp", func(keyName string) (int64, error) {
		return 0, nil
	})

	Dispatch.AddFunc("GetKeys", func(keyName string) ([]string, error) {
		return []string{}, nil
	})

	Dispatch.AddFunc("DeleteKey", func(keyName string) (bool, error) {
		return true, nil
	})

	Dispatch.AddFunc("DeleteRawKey", func(keyName string) (bool, error) {
		return true, nil
	})

	Dispatch.AddFunc("GetKeysAndValues", func(searchString string) (*KeysValuesPair, error) {
		return nil, nil
	})

	Dispatch.AddFunc("GetKeysAndValuesWithFilter", func(searchString string) (*KeysValuesPair, error) {
		return nil, nil
	})

	Dispatch.AddFunc("DeleteKeys", func(keys []string) (bool, error) {
		return true, nil
	})

	Dispatch.AddFunc("Decrement", func(keyName string) error {
		return nil
	})

	Dispatch.AddFunc("IncrememntWithExpire", func(ibd *InboundData) (int64, error) {
		return 0, nil
	})

	Dispatch.AddFunc("AppendToSet", func(ibd *InboundData) error {
		return nil
	})

	Dispatch.AddFunc("SetRollingWindow", func(ibd *InboundData) (int, error) {
		return 0, nil
	})

	Dispatch.AddFunc("GetApiDefinitions", func(dr *DefRequest) (string, error) {
		return "", nil
	})

	Dispatch.AddFunc("GetPolicies", func(orgId string) (string, error) {
		return "", nil
	})

	Dispatch.AddFunc("PurgeAnalyticsData", func(data string) error {
		return nil
	})

	Dispatch.AddFunc("CheckReload", func(clientAddr string, orgId string) (bool, error) {
		return false, nil
	})

	Dispatch.AddFunc("GetKeySpaceUpdate", func(clientAddr string, orgId string) ([]string, error) {
		return []string{}, nil
	})

	Dispatch.AddFunc("GetGroupKeySpaceUpdate", func(clientAddr string, groupData *GroupKeySpaceRequest) ([]string, error) {
		return []string{}, nil
	})

	Dispatch.AddFunc("Ping", func() bool {
		return false
	})

	return Dispatch

}
