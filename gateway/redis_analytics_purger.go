package gateway

import (
	"context"
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

	exp, _ := r.Store.GetExp(analyticsKeyName)
	if exp <= 0 {
		r.Store.SetExp(analyticsKeyName, int64(expireAfter))
	}
}
