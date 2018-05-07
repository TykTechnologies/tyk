package main

import (
	"encoding/json"
	"time"

	"gopkg.in/vmihailenco/msgpack.v2"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
)

// Purger is an interface that will define how the in-memory store will be purged
// of analytics data to prevent it growing too large
type Purger interface {
	PurgeCache()
	PurgeLoop(<-chan time.Time)
}

// RPCPurger will purge analytics data into a Mongo database, requires that the Mongo DB string is specified
// in the Config object
type RPCPurger struct {
	Store storage.Handler
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
func (r RPCPurger) PurgeLoop(ticker <-chan time.Time) {
	for {
		<-ticker
		r.PurgeCache()
	}
}

// PurgeCache will pull the data from the in-memory store and drop it into the specified MongoDB collection
func (r *RPCPurger) PurgeCache() {
	if _, err := RPCFuncClientSingleton.Call("Ping", nil); err != nil {
		log.Error("Can't purge cache, failed to ping RPC: ", err)
		return
	}

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
		emitRPCErrorEvent(rpcFuncClientSingletonCall, "PurgeAnalyticsData", err)
		log.Error("Failed to call purge: ", err)
	}

}

type RedisPurger struct {
	Store storage.Handler
}

func (r RedisPurger) PurgeLoop(ticker <-chan time.Time) {
	for {
		<-ticker
		r.PurgeCache()
	}
}

func (r *RedisPurger) PurgeCache() {
	expireAfter := config.Global().AnalyticsConfig.StorageExpirationTime
	if expireAfter == 0 {
		expireAfter = 60 // 1 minute
	}

	exp, _ := r.Store.GetExp(analyticsKeyName)
	if exp <= 0 {
		r.Store.SetExp(analyticsKeyName, int64(expireAfter))
	}
}
