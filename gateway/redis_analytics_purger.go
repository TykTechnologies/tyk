package gateway

import (
	"context"
	"fmt"
	"time"

	"github.com/TykTechnologies/tyk/config"
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
}

func (r RedisPurger) PurgeLoop(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			r.PurgeCache()
		}
	}
}

func (r *RedisPurger) PurgeCache() {
	expireAfter := config.Global().AnalyticsConfig.StorageExpirationTime
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
