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
type Purger struct {
	Store               storage.Handler
	AnalyticsRecordFunc func() interface{}
}

// Connect Connects to RPC
func (r *Purger) Connect() {
	if !clientIsConnected {
		Log.Error("RPC client is not connected, use Connect method 1st")
	}

	// setup RPC func if needed
	if !addedFuncs["Ping"] {
		dispatcher.AddFunc("Ping", func() bool {
			return false
		})
		addedFuncs["Ping"] = true
	}
	if !addedFuncs["PurgeAnalyticsData"] {
		dispatcher.AddFunc("PurgeAnalyticsData", func(data string) error {
			return nil
		})
		addedFuncs["PurgeAnalyticsData"] = true
	}

	Log.Info("RPC Analytics client using singleton")
}

// PurgeLoop starts the loop that will pull data out of the in-memory
// store and into RPC.
func (r Purger) PurgeLoop(ticker <-chan time.Time) {
	for {
		<-ticker
		r.PurgeCache()
	}
}

// PurgeCache will pull the data from the in-memory store and drop it into the specified MongoDB collection
func (r *Purger) PurgeCache() {
	if !clientIsConnected {
		Log.Error("RPC client is not connected, use Connect method 1st")
	}

	if _, err := FuncClientSingleton("Ping", nil); err != nil {
		Log.WithError(err).Error("Can't purge cache, failed to ping RPC")
		return
	}

	analyticsValues := r.Store.GetAndDeleteSet(analyticsKeyName)
	if len(analyticsValues) == 0 {
		return
	}
	keys := make([]interface{}, len(analyticsValues))

	for i, v := range analyticsValues {
		decoded := r.AnalyticsRecordFunc()
		if err := msgpack.Unmarshal(v.([]byte), &decoded); err != nil {
			Log.WithError(err).Error("Couldn't unmarshal analytics data")
		} else {
			Log.WithField("decoded", decoded).Debug("Decoded Record")
			keys[i] = decoded
		}
	}

	data, err := json.Marshal(keys)
	if err != nil {
		Log.WithError(err).Error("Failed to marshal analytics data")
		return
	}

	// Send keys to RPC
	if _, err := FuncClientSingleton("PurgeAnalyticsData", string(data)); err != nil {
		EmitErrorEvent(FuncClientSingletonCall, "PurgeAnalyticsData", err)
		Log.Warn("Failed to call purge, retrying: ", err)
	}
}
