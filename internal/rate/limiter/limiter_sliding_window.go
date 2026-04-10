package limiter

import (
	"context"
	"time"

	"github.com/TykTechnologies/exp/pkg/limiters"
)

func (l *Limiter) SlidingWindow(ctx context.Context, key string, rate float64, per float64) error {
	var (
		storage limiters.SlidingWindowIncrementer

		capacity = int64(rate)
		ttl      = time.Duration(per * float64(time.Second))
	)

	if l.redis != nil {
		storage = limiters.NewSlidingWindowRedis(l.redis, key)
	} else {
		storage = limiters.LocalSlidingWindow(key)
	}

	// TODO: when doing rate sliding rate limits, the counts for two windows are
	//       used, the full count of the current window, and based on % of window
	//       time that has elapsed, a reduced previous window count.
	//
	//       the epsilon value is used to allow some requests to go over the defined
	//       rate limit at any point of the calculation (start of window, end of ...).
	limiter := limiters.NewSlidingWindow(capacity, ttl, storage, l.clock, 0)

	// Rate limiter returns a zero duration and a possible ErrLimitExhausted when no tokens are available.
	_, err := limiter.Limit(ctx)
	return err
}
