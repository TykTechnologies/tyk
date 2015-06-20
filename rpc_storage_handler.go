package main

import (
	"errors"
	"github.com/garyburd/redigo/redis"
	"github.com/lonelycode/gorpc"
	"github.com/pmylund/go-cache"
	"strings"
	"time"
)

type InboundData struct {
	KeyName      string
	Value        string
	SessionState string
	Timeout      int64
	Per          int64
	Expire       int64
}

type KeysValuesPair struct {
	Keys   []string
	Values []string
}

var ErrorDenied error = errors.New("Access Denied")

// ------------------- CLOUD STORAGE MANAGER -------------------------------

// RPCStorageHandler is a storage manager that uses the redis database.
type RPCStorageHandler struct {
	RPCClient *gorpc.Client
	Client    *gorpc.DispatcherClient
	KeyPrefix string
	HashKeys  bool
	UserKey   string
	Address   string
	cache     *cache.Cache
}

// Connect will establish a connection to the DB
func (r *RPCStorageHandler) Connect() bool {
	// Set up the cache
	r.cache = cache.New(30*time.Second, 15*time.Second)

	r.RPCClient = gorpc.NewTCPClient(r.Address)
	r.RPCClient.Conns = 10
	r.RPCClient.Start()
	d := GetDispatcher()
	r.Client = d.NewFuncClient(r.RPCClient)
	log.Warning("Connected: ", r.Address)
	r.Login()

	return true
}

func (r *RPCStorageHandler) Disconnect() bool {
	r.RPCClient.Stop()

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

func (r *RPCStorageHandler) Login() {
	log.Info("[RPC Store] Login initiated")

	if len(r.UserKey) == 0 {
		log.Fatal("No API Key set!")
	}

	ok, err := r.Client.Call("Login", r.UserKey)
	if err != nil {
		log.Fatal("RPC Login failed: ", err)
	}

	if !ok.(bool) {
		log.Fatal("RPC Login incorrect")
	}
	log.Info("[RPC Store] Login complete")
}

// GetKey will retreive a key from the database
func (r *RPCStorageHandler) GetKey(keyName string) (string, error) {
	start := time.Now() // get current time
	log.Debug("[STORE] Getting WAS: ", keyName)
	log.Debug("[STORE] Getting: ", r.fixKey(keyName))

	// Check the cache first
	if config.SlaveOptions.EnableRPCCache {
		cachedVal, found := r.cache.Get(r.fixKey(keyName))
		if found {
			elapsed := time.Since(start)
			log.Info("GetKey took ", elapsed)
			log.Debug(cachedVal.(string))
			return cachedVal.(string), nil
		}
	}

	// Not cached
	value, err := r.Client.Call("GetKey", r.fixKey(keyName))

	if err != nil {
		if r.IsAccessError(err) {
			r.Login()
			return r.GetKey(keyName)
		}

		log.Debug("Error trying to get value:", err)
		return "", KeyError{}
	}
	elapsed := time.Since(start)
	log.Info("GetKey took ", elapsed)

	if config.SlaveOptions.EnableRPCCache {
		// Cache it
		r.cache.Set(r.fixKey(keyName), value, cache.DefaultExpiration)
	}
	
	return value.(string), nil
}

func (r *RPCStorageHandler) GetExp(keyName string) (int64, error) {
	log.Info("GetExp called")
	value, err := r.Client.Call("GetExp", r.fixKey(keyName))

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
func (r *RPCStorageHandler) SetKey(keyName string, sessionState string, timeout int64) {
	start := time.Now() // get current time
	ibd := InboundData{
		KeyName:      r.fixKey(keyName),
		SessionState: sessionState,
		Timeout:      timeout,
	}

	_, err := r.Client.Call("SetKey", ibd)

	if r.IsAccessError(err) {
		r.Login()
		r.SetKey(keyName, sessionState, timeout)
		return
	}

	elapsed := time.Since(start)
	log.Info("SetKey took ", elapsed)

}

// Decrement will decrement a key in redis
func (r *RPCStorageHandler) Decrement(keyName string) {
	log.Warning("Decrement called")
	_, err := r.Client.Call("Decrement", keyName)
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

	val, err := r.Client.Call("IncrememntWithExpire", ibd)

	if r.IsAccessError(err) {
		r.Login()
		return r.IncrememntWithExpire(keyName, expire)
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

	kvPair, err := r.Client.Call("GetKeysAndValuesWithFilter", searchStr)

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
	kvPair, err := r.Client.Call("GetKeysAndValues", searchStr)

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
	ok, err := r.Client.Call("DeleteKey", r.fixKey(keyName))

	if r.IsAccessError(err) {
		r.Login()
		return r.DeleteKey(keyName)
	}

	return ok.(bool)
}

// DeleteKey will remove a key from the database without prefixing, assumes user knows what they are doing
func (r *RPCStorageHandler) DeleteRawKey(keyName string) bool {
	ok, err := r.Client.Call("DeleteRawKey", keyName)

	if r.IsAccessError(err) {
		r.Login()
		return r.DeleteRawKey(keyName)
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
		ok, err := r.Client.Call("DeleteKeys", asInterface)

		if r.IsAccessError(err) {
			r.Login()
			return r.DeleteKeys(keys)
		}

		return ok.(bool)
	} else {
		log.Debug("RPCStorageHandler called DEL - Nothing to delete")
		return true
	}

	return true
}

// DeleteKeys will remove a group of keys in bulk without a prefix handler
func (r *RPCStorageHandler) DeleteRawKeys(keys []string, prefix string) bool {
	log.Error("DeleteRawKeys Not Implemented")
	return false
}

// StartPubSubHandler will listen for a signal and run the callback with the message
func (r *RPCStorageHandler) StartPubSubHandler(channel string, callback func(redis.Message)) error {
	// psc := redis.PubSubConn{r.pool.Get()}
	// psc.Subscribe(channel)
	// for {
	// 	switch v := psc.Receive().(type) {
	// 	case redis.Message:
	// 		callback(v)

	// 	case redis.Subscription:
	// 		log.Info("Subscription started: ", v.Channel)

	// 	case error:
	// 		log.Error("Redis disconnected or error received, attempting to reconnect: ", v)

	// 		return v
	// 	}
	// }
	// return errors.New("Connection closed.")

	//TODO: implement an alternative!
	log.Warning("NO PUBSUB DEFINED")
	return nil
}

func (r *RPCStorageHandler) Publish(channel string, message string) error {
	// db := r.pool.Get()
	// defer db.Close()
	// if r.pool == nil {
	// 	log.Info("Connection dropped, Connecting..")
	// 	r.Connect()
	// 	r.Publish(channel, message)
	// } else {
	// 	_, err := db.Do("PUBLISH", channel, message)
	// 	if err != nil {
	// 		log.Error("Error trying to set value:")
	// 		log.Error(err)
	// 		return err
	// 	}
	// }

	// TODO: Implement alternative!
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

	_, err := r.Client.Call("AppendToSet", ibd)
	if r.IsAccessError(err) {
		r.Login()
		r.AppendToSet(keyName, value)
		return
	}

}

// SetScrollingWindow is used in the rate limiter to handle rate limits fairly.
func (r *RPCStorageHandler) SetRollingWindow(keyName string, per int64, expire int64) int {
	start := time.Now() // get current time
	ibd := InboundData{
		KeyName: keyName,
		Per:     per,
		Expire:  expire,
	}

	intVal, err := r.Client.Call("SetRollingWindow", ibd)
	if r.IsAccessError(err) {
		r.Login()
		return r.SetRollingWindow(keyName, per, expire)
	}

	elapsed := time.Since(start)
	log.Info("SetRollingWindow took ", elapsed)

	return intVal.(int)

}

func (r RPCStorageHandler) IsAccessError(err error) bool {
	if err != nil {
		if err.Error() == "Access Denied" {
			return true
		}
		return false
	}
	return false
}

// GetAPIDefinitions will pull API definitions from the RPC server
func (r *RPCStorageHandler) GetApiDefinitions(orgId string) string {
	defString, err := r.Client.Call("GetApiDefinitions", orgId)

	if err != nil {
		if r.IsAccessError(err) {
			r.Login()
			return r.GetApiDefinitions(orgId)
		}
	}
	log.Info("API Definitions retrieved")
	return defString.(string)

}

// GetPolicies will pull Policies from the RPC server
func (r *RPCStorageHandler) GetPolicies(orgId string) string {
	defString, err := r.Client.Call("GetPolicies", orgId)
	if err != nil {
		if r.IsAccessError(err) {
			r.Login()
			return r.GetPolicies(orgId)
		}
	}

	return defString.(string)

}

func GetDispatcher() *gorpc.Dispatcher {
	var Dispatch *gorpc.Dispatcher = gorpc.NewDispatcher()

	Dispatch.AddFunc("Login", func(clientAddr string, userKey string) bool {
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

	Dispatch.AddFunc("GetApiDefinitions", func(orgId string) (string, error) {
		return "", nil
	})

	Dispatch.AddFunc("GetPolicies", func(orgId string) (string, error) {
		return "", nil
	})

	Dispatch.AddFunc("PurgeAnalyticsData", func(data string) error {
		return nil
	})

	return Dispatch

}
