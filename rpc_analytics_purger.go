package main

import (
	"encoding/json"
	"github.com/lonelycode/gorpc"
	"gopkg.in/vmihailenco/msgpack.v2"
	"time"
)

// MongoPurger will purge analytics data into a Mongo database, requires that the Mongo DB string is specified
// in the Config object
type RPCPurger struct {
	Store     *RedisStorageManager
	RPCClient *gorpc.Client
	Client    *gorpc.DispatcherClient
	Address   string
}

// Connect Connects to Mongo
func (r *RPCPurger) Connect() {
	log.Info("Connecting to RPC Analytics service")
	r.RPCClient = gorpc.NewTCPClient(r.Address)
	r.RPCClient.Start()
	d := GetDispatcher()
	r.Client = d.NewFuncClient(r.RPCClient)

	return
}

// StartPurgeLoop starts the loop that will be started as a goroutine and pull data out of the in-memory
// store and into MongoDB
func (r RPCPurger) StartPurgeLoop(nextCount int) {
	time.Sleep(time.Duration(nextCount) * time.Second)
	r.PurgeCache()
	r.StartPurgeLoop(nextCount)
}

// PurgeCache will pull the data from the in-memory store and drop it into the specified MongoDB collection
func (r *RPCPurger) PurgeCache() {
	//var AnalyticsValues []interface{}

	AnalyticsValues := r.Store.GetAndDeleteSet(ANALYTICS_KEYNAME)

	if len(AnalyticsValues) > 0 {
		keys := make([]AnalyticsRecord, len(AnalyticsValues), len(AnalyticsValues))

		for i, v := range AnalyticsValues {
			decoded := AnalyticsRecord{}
			err := msgpack.Unmarshal(v.([]byte), &decoded)
			log.Debug("Decoded Record: ", decoded)
			if err != nil {
				log.Error("Couldn't unmarshal analytics data:")
				log.Error(err)
			} else {
				keys[i] = decoded
			}
		}

		data, dErr := json.Marshal(keys)
		if dErr != nil {
			log.Error("Failed to marshal analytics data")
			return
		}

		// Send keys to RPC
		r.Client.Call("PurgeAnalyticsData", string(data))
	}

}
