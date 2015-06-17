package main

import (
	"github.com/garyburd/redigo/redis"
	"github.com/lonelycode/gorpc"
	"strings"
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

// ------------------- CLOUD STORAGE MANAGER -------------------------------

// RPCStorageHandler is a storage manager that uses the redis database.
type RPCStorageHandler struct {
	RPCClient *gorpc.Client
	Client    *gorpc.DispatcherClient
	KeyPrefix string
	HashKeys  bool
}

// Connect will establish a connection to the DB
func (r *RPCStorageHandler) Connect() bool {
	r.RPCClient = gorpc.NewTCPClient(":9090")
	r.RPCClient.Start()
	d := GetDispatcher()
	r.Client = d.NewFuncClient(r.RPCClient)

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

// GetKey will retreive a key from the database
func (r *RPCStorageHandler) GetKey(keyName string) (string, error) {
	log.Debug("[STORE] Getting WAS: ", keyName)
	log.Debug("[STORE] Getting: ", r.fixKey(keyName))

	value, err := r.Client.Call("GetKey", r.fixKey(keyName))

	if err != nil {
		log.Debug("Error trying to get value:", err)
		return "", KeyError{}
	}

	return value.(string), nil
}

func (r *RPCStorageHandler) GetExp(keyName string) (int64, error) {
	value, err := r.Client.Call("GetExp", r.fixKey(keyName))

	if err != nil {
		log.Error("Error trying to get TTL: ", err)
	} else {
		return value.(int64), nil
	}

	return 0, KeyError{}
}

// SetKey will create (or update) a key value in the store
func (r *RPCStorageHandler) SetKey(keyName string, sessionState string, timeout int64) {
	ibd := InboundData{
		KeyName:      r.fixKey(keyName),
		SessionState: sessionState,
		Timeout:      timeout,
	}

	r.Client.Call("SetKey", ibd)

}

// Decrement will decrement a key in redis
func (r *RPCStorageHandler) Decrement(keyName string) {
	r.Client.Call("Decrement", keyName)
}

// IncrementWithExpire will increment a key in redis
func (r *RPCStorageHandler) IncrememntWithExpire(keyName string, expire int64) int64 {

	ibd := InboundData{
		KeyName: keyName,
		Expire:  expire,
	}

	val, _ := r.Client.Call("IncrememntWithExpire", ibd)

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

	kvPair, _ := r.Client.Call("GetKeysAndValuesWithFilter", searchStr)

	returnValues := make(map[string]string)

	for i, v := range kvPair.(*KeysValuesPair).Keys {
		returnValues[r.cleanKey(v)] = kvPair.(*KeysValuesPair).Values[i]
	}

	return returnValues
}

// GetKeysAndValues will return all keys and their values - not to be used lightly
func (r *RPCStorageHandler) GetKeysAndValues() map[string]string {

	searchStr := r.KeyPrefix + "*"
	kvPair, _ := r.Client.Call("GetKeysAndValuesWithFilter", searchStr)

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
	ok, _ := r.Client.Call("DeleteKey", r.fixKey(keyName))

	return ok.(bool)
}

// DeleteKey will remove a key from the database without prefixing, assumes user knows what they are doing
func (r *RPCStorageHandler) DeleteRawKey(keyName string) bool {
	ok, _ := r.Client.Call("DeleteRawKey", keyName)

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
		ok, _ := r.Client.Call("DeleteKeys", asInterface)

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

	r.Client.Call("AppendToSet", ibd)

}

// SetScrollingWindow is used in the rate limiter to handle rate limits fairly.
func (r *RPCStorageHandler) SetRollingWindow(keyName string, per int64, expire int64) int {
	ibd := InboundData{
		KeyName: keyName,
		Per:     per,
		Expire:  expire,
	}

	intVal, _ := r.Client.Call("SetRollingWindow", ibd)

	return intVal.(int)

}

// GetAPIDefinitions will pull API definitions from the RPC server
func (r *RPCStorageHandler) GetApiDefinitions(orgId string) string {
	defString, _ := r.Client.Call("GetApiDefinitions", orgId)

	return defString.(string)

}

// GetPolicies will pull Policies from the RPC server
func (r *RPCStorageHandler) GetPolicies(orgId string) string {
	defString, _ := r.Client.Call("GetPolicies", orgId)

	return defString.(string)

}

func GetDispatcher() *gorpc.Dispatcher {
	var Dispatch *gorpc.Dispatcher = gorpc.NewDispatcher()

	Dispatch.AddFunc("GetKey", func(keyName string) (string, error) {
		return "", nil
	})

	Dispatch.AddFunc("SetKey", func(ibd *InboundData) {

	})

	Dispatch.AddFunc("GetExp", func(keyName string) (int64, error) {
		return 0, nil
	})

	Dispatch.AddFunc("GetKeys", func(keyName string) []string {
		return []string{}
	})

	Dispatch.AddFunc("DeleteKey", func(keyName string) bool {
		return true
	})

	Dispatch.AddFunc("DeleteRawKey", func(keyName string) bool {
		return true
	})

	Dispatch.AddFunc("GetKeysAndValues", func(searchString string) *KeysValuesPair {
		return nil
	})

	Dispatch.AddFunc("GetKeysAndValuesWithFilter", func(searchString string) *KeysValuesPair {
		return nil
	})

	Dispatch.AddFunc("DeleteKeys", func(keys []string) bool {
		return true
	})

	Dispatch.AddFunc("Decrement", func(keyName string) {

	})

	Dispatch.AddFunc("IncrememntWithExpire", func(ibd *InboundData) int64 {
		return 0
	})

	Dispatch.AddFunc("AppendToSet", func(ibd *InboundData) {

	})

	Dispatch.AddFunc("SetRollingWindow", func(ibd *InboundData) int {
		return 0
	})

	Dispatch.AddFunc("GetApiDefinitions", func(orgId string) string {
		return ""
	})

	Dispatch.AddFunc("GetPolicies", func(orgId string) string {
		return ""
	})

	Dispatch.AddFunc("PurgeAnalyticsData", func(data string) {

	})

	return Dispatch

}
