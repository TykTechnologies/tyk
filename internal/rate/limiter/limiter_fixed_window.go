package limiter

import (
	"context"
	"time"

	"github.com/TykTechnologies/exp/pkg/limiters"
)

func (l *Limiter) FixedWindow(ctx context.Context, key string, rate float64, per float64) error {
	var (
		storage limiters.FixedWindowIncrementer

		capacity = int64(rate)
		ttl      = time.Duration(per * float64(time.Second))
	)

	rateLimitPrefix := Prefix(l.prefix, key)

	if l.redis != nil {
		storage = limiters.NewFixedWindowRedis(l.redis, rateLimitPrefix)
	} else {
		storage = limiters.LocalFixedWindow(rateLimitPrefix)
	}

	limiter := limiters.NewFixedWindow(capacity, ttl, storage, l.clock)

	// Rate limiter returns a zero duration and a possible ErrLimitExhausted when no tokens are available.
	_, err := limiter.Limit(ctx)
	return err
}
