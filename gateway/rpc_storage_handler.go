package gateway

import (
	"strconv"
	"strings"
	"time"

	cache "github.com/pmylund/go-cache"

	"github.com/TykTechnologies/tyk/rpc"

	"github.com/garyburd/redigo/redis"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"

	"github.com/sirupsen/logrus"
)

var (
	dispatcherFuncs = map[string]interface{}{
		"Login": func(clientAddr, userKey string) bool {
			return false
		},
		"LoginWithGroup": func(clientAddr string, groupData *apidef.GroupLoginRequest) bool {
			return false
		},
		"GetKey": func(keyName string) (string, error) {
			return "", nil
		},
		"SetKey": func(ibd *apidef.InboundData) error {
			return nil
		},
		"GetExp": func(keyName string) (int64, error) {
			return 0, nil
		},
		"GetKeys": func(keyName string) ([]string, error) {
			return nil, nil
		},
		"DeleteKey": func(keyName string) (bool, error) {
			return true, nil
		},
		"DeleteRawKey": func(keyName string) (bool, error) {
			return true, nil
		},
		"GetKeysAndValues": func(searchString string) (*apidef.KeysValuesPair, error) {
			return nil, nil
		},
		"GetKeysAndValuesWithFilter": func(searchString string) (*apidef.KeysValuesPair, error) {
			return nil, nil
		},
		"DeleteKeys": func(keys []string) (bool, error) {
			return true, nil
		},
		"Decrement": func(keyName string) error {
			return nil
		},
		"IncrememntWithExpire": func(ibd *apidef.InboundData) (int64, error) {
			return 0, nil
		},
		"AppendToSet": func(ibd *apidef.InboundData) error {
			return nil
		},
		"SetRollingWindow": func(ibd *apidef.InboundData) (int, error) {
			return 0, nil
		},
		"GetApiDefinitions": func(dr *apidef.DefRequest) (string, error) {
			return "", nil
		},
		"GetPolicies": func(orgId string) (string, error) {
			return "", nil
		},
		"PurgeAnalyticsData": func(data string) error {
			return nil
		},
		"CheckReload": func(clientAddr, orgId string) (bool, error) {
			return false, nil
		},
		"GetKeySpaceUpdate": func(clientAddr, orgId string) ([]string, error) {
			return nil, nil
		},
		"GetGroupKeySpaceUpdate": func(clientAddr string, groupData *apidef.GroupKeySpaceRequest) ([]string, error) {
			return nil, nil
		},
		"Ping": func() bool {
			return false
		},
	}
)

// RPCStorageHandler is a storage manager that uses the redis database.
type RPCStorageHandler struct {
	KeyPrefix        string
	HashKeys         bool
	SuppressRegister bool
}

var RPCGlobalCache = cache.New(30*time.Second, 15*time.Second)

// Connect will establish a connection to the RPC
func (r *RPCStorageHandler) Connect() bool {
	slaveOptions := config.Global().SlaveOptions
	rpcConfig := rpc.Config{
		UseSSL:                slaveOptions.UseSSL,
		SSLInsecureSkipVerify: slaveOptions.SSLInsecureSkipVerify,
		ConnectionString:      slaveOptions.ConnectionString,
		RPCKey:                slaveOptions.RPCKey,
		APIKey:                slaveOptions.APIKey,
		GroupID:               slaveOptions.GroupID,
		CallTimeout:           slaveOptions.CallTimeout,
		PingTimeout:           slaveOptions.PingTimeout,
		RPCPoolSize:           slaveOptions.RPCPoolSize,
	}

	return rpc.Connect(
		rpcConfig,
		r.SuppressRegister,
		dispatcherFuncs,
		func(userKey string, groupID string) interface{} {
			return apidef.GroupLoginRequest{
				UserKey: userKey,
				GroupID: groupID,
			}
		},
		func() {
			reloadURLStructure(nil)
		},
		DoReload,
	)
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

// GetKey will retrieve a key from the database
func (r *RPCStorageHandler) GetKey(keyName string) (string, error) {
	start := time.Now() // get current time
	log.Debug("[STORE] Getting WAS: ", keyName)
	log.Debug("[STORE] Getting: ", r.fixKey(keyName))

	value, err := r.GetRawKey(r.fixKey(keyName))

	elapsed := time.Since(start)
	log.Debug("GetKey took ", elapsed)

	return value, err
}

func (r *RPCStorageHandler) GetRawKey(keyName string) (string, error) {
	// Check the cache first
	if config.Global().SlaveOptions.EnableRPCCache {
		log.Debug("Using cache for: ", keyName)
		cachedVal, found := RPCGlobalCache.Get(keyName)
		log.Debug("--> Found? ", found)
		if found {
			return cachedVal.(string), nil
		}
	}

	value, err := rpc.FuncClientSingleton("GetKey", keyName)
	if err != nil {
		rpc.EmitErrorEventKv(
			rpc.FuncClientSingletonCall,
			"GetKey",
			err,
			map[string]string{
				"keyName": keyName,
			},
		)
		if r.IsAccessError(err) {
			if rpc.Login() {
				return r.GetRawKey(keyName)
			}
		}
		log.Debug("Error trying to get value:", err)
		return "", storage.ErrKeyNotFound
	}
	if config.Global().SlaveOptions.EnableRPCCache {
		// Cache key
		RPCGlobalCache.Set(keyName, value, cache.DefaultExpiration)
	}
	//return hash key without prefix so it doesnt get double prefixed in redis
	return value.(string), nil
}

func (r *RPCStorageHandler) GetMultiKey(keyNames []string) ([]string, error) {
	for _, key := range keyNames {
		if value, err := r.GetKey(key); err != nil {
			return nil, err
		} else {
			return []string{value}, nil
		}
	}

	return nil, nil
}

func (r *RPCStorageHandler) GetExp(keyName string) (int64, error) {
	log.Debug("GetExp called")
	value, err := rpc.FuncClientSingleton("GetExp", r.fixKey(keyName))
	if err != nil {
		rpc.EmitErrorEventKv(
			rpc.FuncClientSingletonCall,
			"GetExp",
			err,
			map[string]string{
				"keyName":      keyName,
				"fixedKeyName": r.fixKey(keyName),
			},
		)
		if r.IsAccessError(err) {
			if rpc.Login() {
				return r.GetExp(keyName)
			}
		}
		log.Error("Error trying to get TTL: ", err)
		return 0, storage.ErrKeyNotFound
	}
	return value.(int64), nil
}

func (r *RPCStorageHandler) SetExp(keyName string, timeout int64) error {
	log.Error("RPCStorageHandler.SetExp - Not Implemented")
	return nil
}

// SetKey will create (or update) a key value in the store
func (r *RPCStorageHandler) SetKey(keyName, session string, timeout int64) error {
	start := time.Now() // get current time
	ibd := apidef.InboundData{
		KeyName:      r.fixKey(keyName),
		SessionState: session,
		Timeout:      timeout,
	}

	_, err := rpc.FuncClientSingleton("SetKey", ibd)
	if err != nil {
		rpc.EmitErrorEventKv(
			rpc.FuncClientSingletonCall,
			"SetKey",
			err,
			map[string]string{
				"keyName":      keyName,
				"fixedKeyName": ibd.KeyName,
			},
		)

		if r.IsAccessError(err) {
			if rpc.Login() {
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
	_, err := rpc.FuncClientSingleton("Decrement", keyName)
	if err != nil {
		rpc.EmitErrorEventKv(
			rpc.FuncClientSingletonCall,
			"Decrement",
			err,
			map[string]string{
				"keyName": keyName,
			},
		)
	}
	if r.IsAccessError(err) {
		if rpc.Login() {
			r.Decrement(keyName)
			return
		}
	}
}

// IncrementWithExpire will increment a key in redis
func (r *RPCStorageHandler) IncrememntWithExpire(keyName string, expire int64) int64 {

	ibd := apidef.InboundData{
		KeyName: keyName,
		Expire:  expire,
	}

	val, err := rpc.FuncClientSingleton("IncrememntWithExpire", ibd)
	if err != nil {
		rpc.EmitErrorEventKv(
			rpc.FuncClientSingletonCall,
			"IncrememntWithExpire",
			err,
			map[string]string{
				"keyName": keyName,
			},
		)
	}
	if r.IsAccessError(err) {
		if rpc.Login() {
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
	log.Error("RPCStorageHandler.GetKeys - Not Implemented")
	return nil
}

// GetKeysAndValuesWithFilter will return all keys and their values with a filter
func (r *RPCStorageHandler) GetKeysAndValuesWithFilter(filter string) map[string]string {

	searchStr := r.KeyPrefix + r.hashKey(filter) + "*"
	log.Debug("[STORE] Getting list by: ", searchStr)

	kvPair, err := rpc.FuncClientSingleton("GetKeysAndValuesWithFilter", searchStr)
	if err != nil {
		rpc.EmitErrorEventKv(
			rpc.FuncClientSingletonCall,
			"GetKeysAndValuesWithFilter",
			err,
			map[string]string{
				"searchStr": searchStr,
			},
		)

		if r.IsAccessError(err) {
			if rpc.Login() {
				return r.GetKeysAndValuesWithFilter(filter)
			}
		}

		return nil
	}

	returnValues := make(map[string]string)

	for i, v := range kvPair.(*apidef.KeysValuesPair).Keys {
		returnValues[r.cleanKey(v)] = kvPair.(*apidef.KeysValuesPair).Values[i]
	}

	return returnValues
}

// GetKeysAndValues will return all keys and their values - not to be used lightly
func (r *RPCStorageHandler) GetKeysAndValues() map[string]string {

	searchStr := r.KeyPrefix + "*"

	kvPair, err := rpc.FuncClientSingleton("GetKeysAndValues", searchStr)
	if err != nil {
		rpc.EmitErrorEvent(rpc.FuncClientSingletonCall, "GetKeysAndValues", err)

		if r.IsAccessError(err) {
			if rpc.Login() {
				return r.GetKeysAndValues()
			}
		}

		return nil
	}

	returnValues := make(map[string]string)
	for i, v := range kvPair.(*apidef.KeysValuesPair).Keys {
		returnValues[r.cleanKey(v)] = kvPair.(*apidef.KeysValuesPair).Values[i]
	}

	return returnValues

}

// DeleteKey will remove a key from the database
func (r *RPCStorageHandler) DeleteKey(keyName string) bool {

	log.Debug("DEL Key was: ", keyName)
	log.Debug("DEL Key became: ", r.fixKey(keyName))
	ok, err := rpc.FuncClientSingleton("DeleteKey", r.fixKey(keyName))
	if err != nil {
		rpc.EmitErrorEventKv(
			rpc.FuncClientSingletonCall,
			"DeleteKey",
			err,
			map[string]string{
				"keyName":      keyName,
				"fixedKeyName": r.fixKey(keyName),
			},
		)

		if r.IsAccessError(err) {
			if rpc.Login() {
				return r.DeleteKey(keyName)
			}
		}
	}

	return ok == true
}

func (r *RPCStorageHandler) DeleteAllKeys() bool {
	log.Warning("Not implementated")
	return false
}

// DeleteKey will remove a key from the database without prefixing, assumes user knows what they are doing
func (r *RPCStorageHandler) DeleteRawKey(keyName string) bool {
	ok, err := rpc.FuncClientSingleton("DeleteRawKey", keyName)
	if err != nil {
		rpc.EmitErrorEventKv(
			rpc.FuncClientSingletonCall,
			"DeleteRawKey",
			err,
			map[string]string{
				"keyName": keyName,
			},
		)

		if r.IsAccessError(err) {
			if rpc.Login() {
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
		ok, err := rpc.FuncClientSingleton("DeleteKeys", asInterface)
		if err != nil {
			rpc.EmitErrorEventKv(
				rpc.FuncClientSingletonCall,
				"DeleteKeys",
				err,
				map[string]string{
					"keys":        strings.Join(keys, ","),
					"asInterface": strings.Join(asInterface, ","),
				},
			)

			if r.IsAccessError(err) {
				if rpc.Login() {
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
	log.Warning("RPCStorageHandler.StartPubSubHandler - NO PUBSUB DEFINED")
	return nil
}

func (r *RPCStorageHandler) Publish(channel, message string) error {
	log.Warning("RPCStorageHandler.Publish - NO PUBSUB DEFINED")
	return nil
}

func (r *RPCStorageHandler) GetAndDeleteSet(keyName string) []interface{} {
	log.Error("RPCStorageHandler.GetAndDeleteSet - Not implemented, please disable your purger")
	return nil
}

func (r *RPCStorageHandler) AppendToSet(keyName, value string) {
	ibd := apidef.InboundData{
		KeyName: keyName,
		Value:   value,
	}

	_, err := rpc.FuncClientSingleton("AppendToSet", ibd)
	if err != nil {
		rpc.EmitErrorEventKv(
			rpc.FuncClientSingletonCall,
			"AppendToSet",
			err,
			map[string]string{
				"keyName": keyName,
			},
		)
	}
	if r.IsAccessError(err) {
		if rpc.Login() {
			r.AppendToSet(keyName, value)
		}
	}
}

func (r *RPCStorageHandler) AppendToSetPipelined(key string, values []string) {
	// just falls back to AppendToSet
	// TODO: introduce new RPC method for pipelined operation
	for _, val := range values {
		r.AppendToSet(key, val)
	}
}

// SetScrollingWindow is used in the rate limiter to handle rate limits fairly.
func (r *RPCStorageHandler) SetRollingWindow(keyName string, per int64, val string, pipeline bool) (int, []interface{}) {
	start := time.Now() // get current time
	ibd := apidef.InboundData{
		KeyName: keyName,
		Per:     per,
		Expire:  -1,
	}

	intVal, err := rpc.FuncClientSingleton("SetRollingWindow", ibd)
	if err != nil {
		rpc.EmitErrorEventKv(
			rpc.FuncClientSingletonCall,
			"SetRollingWindow",
			err,
			map[string]string{
				"keyName": keyName,
				"per":     strconv.Itoa(int(per)),
			},
		)

		if r.IsAccessError(err) {
			if rpc.Login() {
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

func (r *RPCStorageHandler) GetRollingWindow(keyName string, per int64, pipeline bool) (int, []interface{}) {
	log.Warning("Not Implemented!")
	return 0, nil
}

func (r RPCStorageHandler) GetSet(keyName string) (map[string]string, error) {
	log.Error("RPCStorageHandler.GetSet - Not implemented")
	return nil, nil
}

func (r RPCStorageHandler) AddToSet(keyName, value string) {
	log.Error("RPCStorageHandler.AddToSet - Not implemented")
}

func (r RPCStorageHandler) RemoveFromSet(keyName, value string) {
	log.Error("RPCStorageHandler.RemoveFromSet - Not implemented")
}

func (r RPCStorageHandler) IsAccessError(err error) bool {
	if err != nil {
		return err.Error() == "Access Denied"
	}
	return false
}

// GetAPIDefinitions will pull API definitions from the RPC server
func (r *RPCStorageHandler) GetApiDefinitions(orgId string, tags []string) string {
	dr := apidef.DefRequest{
		OrgId: orgId,
		Tags:  tags,
	}

	defString, err := rpc.FuncClientSingleton("GetApiDefinitions", dr)
	if err != nil {
		rpc.EmitErrorEventKv(
			rpc.FuncClientSingletonCall,
			"GetApiDefinitions",
			err,
			map[string]string{
				"orgId": orgId,
				"tags":  strings.Join(tags, ","),
			},
		)

		if r.IsAccessError(err) {
			if rpc.Login() {
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
	defString, err := rpc.FuncClientSingleton("GetPolicies", orgId)
	if err != nil {
		rpc.EmitErrorEventKv(
			rpc.FuncClientSingletonCall,
			"GetPolicies",
			err,
			map[string]string{
				"orgId": orgId,
			},
		)

		if r.IsAccessError(err) {
			if rpc.Login() {
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
	reload, err := rpc.FuncClientSingleton("CheckReload", orgId)
	if err != nil {
		rpc.EmitErrorEventKv(
			rpc.FuncClientSingletonCall,
			"CheckReload",
			err,
			map[string]string{
				"orgId": orgId,
			},
		)
		if r.IsAccessError(err) {
			log.Warning("[RPC STORE] CheckReload: Not logged in")
			if rpc.Login() {
				r.CheckForReload(orgId)
			}
		} else if !strings.Contains(err.Error(), "Cannot obtain response during") {
			log.Warning("[RPC STORE] RPC Reload Checker encountered unexpected error: ", err)
		}

		time.Sleep(1 * time.Second)
	} else if reload == true {
		// Do the reload!
		log.Warning("[RPC STORE] Received Reload instruction!")
		go func() {
			MainNotifier.Notify(Notification{Command: NoticeGroupReload})
		}()
	}
}

func (r *RPCStorageHandler) StartRPCLoopCheck(orgId string) {
	if config.Global().SlaveOptions.DisableKeySpaceSync {
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
			log.WithError(err).WithFields(logrus.Fields{
				"prefix": "RPC Conn Mgr",
			}).Info("Can't connect to RPC layer")

			if r.IsAccessError(err) {
				if rpc.Login() {
					continue
				}
			}

			if strings.Contains(err.Error(), "Cannot obtain response during timeout") {
				continue
			}
		}

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
	if groupID := config.Global().SlaveOptions.GroupID; groupID == "" {
		funcName = "GetKeySpaceUpdate"
		req = orgId
		reqData["orgId"] = orgId
	} else {
		funcName = "GetGroupKeySpaceUpdate"
		req = apidef.GroupKeySpaceRequest{
			OrgID:   orgId,
			GroupID: groupID,
		}
		reqData["orgId"] = orgId
		reqData["GroupID"] = groupID
	}

	keys, err = rpc.FuncClientSingleton(funcName, req)
	if err != nil {
		rpc.EmitErrorEventKv(
			rpc.FuncClientSingletonCall,
			funcName,
			err,
			reqData,
		)
		if r.IsAccessError(err) {
			if rpc.Login() {
				r.CheckForKeyspaceChanges(orgId)
			}
		}
		log.Warning("Keyspace warning: ", err)
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

func getSessionAndCreate(keyName string, r *RPCStorageHandler) {
	newKeyName := "apikey-" + storage.HashStr(keyName)
	sessionString, err := r.GetRawKey(keyName)
	if err != nil {
		log.Error("Key not found in master - skipping")
	} else {
		handleAddKey(keyName, newKeyName[7:], sessionString, "-1")
	}
}

func (r *RPCStorageHandler) ProcessKeySpaceChanges(keys []string) {
	keysToReset := map[string]bool{}

	for _, key := range keys {
		splitKeys := strings.Split(key, ":")
		if len(splitKeys) > 1 && splitKeys[1] == "resetQuota" {
			keysToReset[splitKeys[0]] = true
		}
	}

	for _, key := range keys {
		splitKeys := strings.Split(key, ":")
		_, resetQuota := keysToReset[splitKeys[0]]
		if len(splitKeys) > 1 && splitKeys[1] == "hashed" {
			key = splitKeys[0]
			log.Info("--> removing cached (hashed) key: ", splitKeys[0])
			handleDeleteHashedKey(splitKeys[0], "", resetQuota)
			getSessionAndCreate(splitKeys[0], r)
		} else {
			log.Info("--> removing cached key: ", key)
			handleDeleteKey(key, "-1", resetQuota)
			getSessionAndCreate(splitKeys[0], r)
		}
		SessionCache.Delete(key)
		RPCGlobalCache.Delete(r.KeyPrefix + key)
	}
	// Notify rest of gateways in cluster to flush cache
	n := Notification{
		Command: KeySpaceUpdateNotification,
		Payload: strings.Join(keys, ","),
	}
	MainNotifier.Notify(n)
}

func (r *RPCStorageHandler) DeleteScanMatch(pattern string) bool {
	log.Error("RPCStorageHandler.DeleteScanMatch - Not implemented")
	return false
}

func (r *RPCStorageHandler) GetKeyPrefix() string {
	log.Error("RPCStorageHandler.GetKeyPrefix - Not implemented")
	return ""
}

func (r *RPCStorageHandler) AddToSortedSet(keyName, value string, score float64) {
	log.Error("RPCStorageHandler.AddToSortedSet - Not implemented")
}

func (r *RPCStorageHandler) GetSortedSetRange(keyName, scoreFrom, scoreTo string) ([]string, []float64, error) {
	log.Error("RPCStorageHandler.GetSortedSetRange - Not implemented")
	return nil, nil, nil
}

func (r *RPCStorageHandler) RemoveSortedSetRange(keyName, scoreFrom, scoreTo string) error {
	log.Error("RPCStorageHandler.RemoveSortedSetRange - Not implemented")
	return nil
}
