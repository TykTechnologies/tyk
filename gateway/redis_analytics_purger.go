package gateway

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/TykTechnologies/tyk/storage"
)

// Purger is an interface that will define how the in-memory store will be purged
// of analytics data to prevent it growing too large
type Purger interface {
	PurgeCache()
	PurgeLoop(<-chan time.Time)
}

type RedisPurger struct {
	Store storage.Handler
	Gw    *Gateway `json:"-"`
}

func (r RedisPurger) PurgeLoop(ctx context.Context) {
	interval := r.purgeInterval()
	tick := time.NewTimer(r.initialPurgeDelay(interval))
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			r.PurgeCache()
			tick.Reset(interval)
		}
	}
}

func (r RedisPurger) purgeInterval() time.Duration {
	if r.Gw == nil {
		return 10 * time.Second
	}

	interval := r.Gw.GetConfig().AnalyticsConfig.PurgeInterval
	if interval <= 0 {
		return 10 * time.Second
	}

	d := time.Duration(float64(interval) * float64(time.Second))
	if d < time.Second {
		return time.Second
	}

	return d
}

func (r RedisPurger) initialPurgeDelay(interval time.Duration) time.Duration {
	if interval <= time.Second {
		return interval
	}

	return time.Duration(rand.New(rand.NewSource(time.Now().UnixNano())).Int63n(int64(interval)))
}

func (r *RedisPurger) PurgeCache() {
	if r.Gw != nil && r.Gw.StorageConnectionHandler != nil && !r.Gw.StorageConnectionHandler.Connected() {
		return
	}

	expireAfter := r.Gw.GetConfig().AnalyticsConfig.StorageExpirationTime
	if expireAfter == -1 {
		return
	}
	if expireAfter == 0 {
		expireAfter = 60 // 1 minute
	}

	for i := -1; i < 10; i++ {
		var analyticsKey string
		if i == -1 {
			//if it's the first iteration, we look for tyk-system-analytics to maintain backwards compatibility or if analytics_config.enable_multiple_analytics_keys is disabled in the gateway
			analyticsKey = analyticsKeyName
		} else {
			analyticsKey = fmt.Sprintf("%v_%v", analyticsKeyName, i)
		}
		exp, _ := r.Store.GetExp(analyticsKey)
		if exp == -1 {
			r.Store.SetExp(analyticsKey, int64(expireAfter))
		}
	}
}
