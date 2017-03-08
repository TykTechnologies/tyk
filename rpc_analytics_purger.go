package main

import (
	"encoding/json"
	"time"

	"gopkg.in/vmihailenco/msgpack.v2"
)

// Purger is an interface that will define how the in-memory store will be purged
// of analytics data to prevent it growing too large
type Purger interface {
	PurgeCache()
	PurgeLoop(time.Duration)
}

// RPCPurger will purge analytics data into a Mongo database, requires that the Mongo DB string is specified
// in the Config object
type RPCPurger struct {
	Store *RedisClusterStorageManager
}

// Connect Connects to RPC
func (r *RPCPurger) Connect() {
	if RPCClientIsConnected && RPCCLientSingleton != nil && RPCFuncClientSingleton != nil {
		log.Info("RPC Analytics client using singleton")
		return
	}
}

// PurgeLoop starts the loop that will pull data out of the in-memory
// store and into RPC.
func (r RPCPurger) PurgeLoop(sleep time.Duration) {
	for {
		time.Sleep(sleep)
		r.PurgeCache()
	}
}

// PurgeCache will pull the data from the in-memory store and drop it into the specified MongoDB collection
func (r *RPCPurger) PurgeCache() {
	analyticsValues := r.Store.GetAndDeleteSet(analyticsKeyName)
	if len(analyticsValues) == 0 {
		return
	}
	keys := make([]AnalyticsRecord, len(analyticsValues))

	for i, v := range analyticsValues {
		decoded := AnalyticsRecord{}
		if err := msgpack.Unmarshal(v.([]byte), &decoded); err != nil {
			log.Error("Couldn't unmarshal analytics data: ", err)
		} else {
			log.Debug("Decoded Record: ", decoded)
			keys[i] = decoded
		}
	}

	data, err := json.Marshal(keys)
	if err != nil {
		log.Error("Failed to marshal analytics data")
		return
	}

	// Send keys to RPC
	if _, err := RPCFuncClientSingleton.Call("PurgeAnalyticsData", string(data)); err != nil {
		log.Error("Failed to call purge: ", err)
	}

}
