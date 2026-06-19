package limiter

import (
	"context"
	"time"

	"github.com/TykTechnologies/exp/pkg/limiters"
)

// SW-REQ-018
func (l *Limiter) FixedWindow(ctx context.Context, key string, rate float64, per float64) (time.Duration, error) {
	var (
		storage limiters.FixedWindowIncrementer

		capacity = int64(rate)
		ttl      = time.Duration(per * float64(time.Second))
	)

	if l.redis != nil {
		storage = limiters.NewFixedWindowRedis(l.redis, key)
	} else {
		storage = limiters.LocalFixedWindow(key)
	}

	limiter := limiters.NewFixedWindow(capacity, ttl, storage, l.clock)

	// Rate limiter returns a wait duration and a possible ErrLimitExhausted when no tokens are available.
	return limiter.Limit(ctx)
}
