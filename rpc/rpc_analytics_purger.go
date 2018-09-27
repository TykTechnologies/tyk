package rpc

import (
	"encoding/json"
	"time"

	"gopkg.in/vmihailenco/msgpack.v2"

	"github.com/TykTechnologies/tyk/storage"
)

const analyticsKeyName = "tyk-system-analytics"

// RPCPurger will purge analytics data into a Mongo database, requires that the Mongo DB string is specified
// in the Config object
type RPCPurger struct {
	Store      storage.Handler
	RecordFunc func() interface{}
}

// Connect Connects to RPC
func (r *RPCPurger) Connect() {
	if RPCClientIsConnected && RPCCLientSingleton != nil && RPCFuncClientSingleton != nil {
		Log.Info("RPC Analytics client using singleton")
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
		Log.Error("Can't purge cache, failed to ping RPC: ", err)
		return
	}

	analyticsValues := r.Store.GetAndDeleteSet(analyticsKeyName)
	if len(analyticsValues) == 0 {
		return
	}
	keys := make([]interface{}, len(analyticsValues))

	for i, v := range analyticsValues {
		decoded := r.RecordFunc()
		if err := msgpack.Unmarshal(v.([]byte), &decoded); err != nil {
			Log.Error("Couldn't unmarshal analytics data: ", err)
		} else {
			Log.Debug("Decoded Record: ", decoded)
			keys[i] = decoded
		}
	}

	data, err := json.Marshal(keys)
	if err != nil {
		Log.Error("Failed to marshal analytics data")
		return
	}

	// Send keys to RPC
	if _, err := RPCFuncClientSingleton.Call("PurgeAnalyticsData", string(data)); err != nil {
		emitRPCErrorEvent(rpcFuncClientSingletonCall, "PurgeAnalyticsData", err)
		Log.Warn("Failed to call purge, retrying: ", err)
	}

}
