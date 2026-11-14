package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/TykTechnologies/tyk-pump/analytics"

	"github.com/vmihailenco/msgpack"

	"github.com/TykTechnologies/tyk/storage"
)

const ANALYTICS_KEYNAME = "tyk-system-analytics"

// RPCPurger will purge analytics data into a Mongo database, requires that the Mongo DB string is specified
// in the Config object
type Purger struct {
	Store storage.Handler
}

// Connect Connects to RPC
func (r *Purger) Connect() {
	if !values.ClientIsConnected() {
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
func (r Purger) PurgeLoop(ctx context.Context, interval time.Duration) {
	tick := time.NewTicker(interval * time.Second)

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			r.PurgeCache()
		}
	}
}

// PurgeCache will pull the data from the in-memory store and drop it into the specified MongoDB collection
func (r *Purger) PurgeCache() {

	if !values.ClientIsConnected() {
		Log.Error("RPC client is not connected, use Connect method 1st")
	}

	if _, err := FuncClientSingleton("Ping", nil); err != nil {
		Log.WithError(err).Error("Can't purge cache, failed to ping RPC")
		return
	}

	for i := -1; i < 10; i++ {
		var analyticsKeyName string
		if i == -1 {
			//if it's the first iteration, we look for tyk-system-analytics to maintain backwards compatibility or if analytics_config.enable_multiple_analytics_keys is disabled in the gateway
			analyticsKeyName = ANALYTICS_KEYNAME
		} else {
			// keyname + serializationmethod
			analyticsKeyName = fmt.Sprintf("%v_%v", ANALYTICS_KEYNAME, i)
		}

		// Remember the remaining TTL so that records put back after a failed
		// purge still expire on the original schedule (see RedisPurger).
		var expiresAt time.Time
		if ttl, err := r.Store.GetExp(analyticsKeyName); err != nil {
			Log.WithError(err).Debug("Failed to read expiry of analytics records")
		} else if ttl >= 0 {
			// Redis rounds TTL to whole seconds: 0 means less than half a
			// second is left, not that the key has no expiry (-1).
			expiresAt = time.Now().Add(time.Duration(ttl) * time.Second)
		}

		analyticsValues := r.Store.GetAndDeleteSet(analyticsKeyName)
		if len(analyticsValues) == 0 {
			continue
		}
		keys, failedRecords := processAnalyticsValues(analyticsValues)
		Log.Debugf("could not decode %v records", failedRecords)

		data, err := json.Marshal(keys)
		if err != nil {
			Log.WithError(err).Error("Failed to marshal analytics data")
			return
		}

		// Send keys to RPC
		if _, err := FuncClientSingleton("PurgeAnalyticsData", string(data)); err != nil {
			EmitErrorEvent(FuncClientSingletonCall, "PurgeAnalyticsData", err)
			Log.WithError(err).Warn("Failed to call purge, analytics will be retried on the next purge cycle")
			r.restoreAnalyticsValues(analyticsKeyName, analyticsValues, expiresAt)
		}

	}
}

// restoreAnalyticsValues puts records popped by GetAndDeleteSet back to Redis
// after a failed purge, so they are retried on the next cycle instead of
// being lost. The key keeps the expiry it had before the pop, minus the time
// spent on the failed call: otherwise a slow failing MDCB would keep the
// records alive forever, and Redis would grow without bound. A zero expiresAt
// means the key had no expiry.
func (r *Purger) restoreAnalyticsValues(analyticsKeyName string, analyticsValues []interface{}, expiresAt time.Time) {
	var ttl int64
	if !expiresAt.IsZero() {
		// Round like Redis does, so repeated failed cycles don't drift
		// the expiry earlier than its original schedule.
		ttl = int64((time.Until(expiresAt) + time.Second/2) / time.Second)
		if ttl <= 0 {
			Log.Warnf("Dropping %d analytics records that expired during the failed purge", len(analyticsValues))
			return
		}
	}

	raw := make([][]byte, 0, len(analyticsValues))
	for _, v := range analyticsValues {
		switch val := v.(type) {
		case string:
			raw = append(raw, []byte(val))
		case []byte:
			raw = append(raw, val)
		default:
			Log.Errorf("Dropping analytics record of unexpected type %T", v)
		}
	}
	if len(raw) == 0 {
		return
	}

	if pipelined, ok := r.Store.(interface {
		AppendToSetPipelined(string, [][]byte)
	}); ok {
		pipelined.AppendToSetPipelined(analyticsKeyName, raw)
	} else {
		for _, v := range raw {
			r.Store.AppendToSet(analyticsKeyName, string(v))
		}
	}

	if ttl > 0 {
		if err := r.Store.SetExp(analyticsKeyName, ttl); err != nil {
			Log.WithError(err).Error("Failed to restore expiry of analytics records")
		}
	}
}

func processAnalyticsValues(analyticsValues []interface{}) ([]interface{}, int) {
	keys := make([]interface{}, len(analyticsValues))
	failedRecords := 0

	for i, v := range analyticsValues {
		decoded, err := decodeAnalyticsRecord(v)
		if err != nil {
			failedRecords++
			Log.WithError(err).Error("Couldn't unmarshal analytics data")
		} else {
			Log.WithField("decoded", decoded).Debug("Decoded Record")
			keys[i] = decoded
		}
	}

	return keys, failedRecords
}

func decodeAnalyticsRecord(encoded interface{}) (analytics.AnalyticsRecord, error) {
	decoded := analytics.AnalyticsRecord{}
	err := msgpack.Unmarshal([]byte(encoded.(string)), &decoded)
	if err != nil {
		return decoded, err
	}
	return decoded, nil
}
