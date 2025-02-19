package limiter

import (
	"context"
	"time"

	"github.com/TykTechnologies/exp/pkg/limiters"
)

func (l *Limiter) LeakyBucket(ctx context.Context, key string, rate float64, per float64) error {
	var (
		storage limiters.LeakyBucketStateBackend
		locker  limiters.DistLocker

		capacity   = int64(rate)
		ttl        = time.Duration(per * float64(time.Second))
		outputRate = time.Duration((per / rate) * float64(time.Second))
		raceCheck  = false
	)

	locker = l.Locker(key)
	if l.redis != nil {
		storage = limiters.NewLeakyBucketRedis(l.redis, key, ttl, raceCheck)
	} else {
		storage = limiters.LocalLeakyBucket(key)
	}

	limiter := limiters.NewLeakyBucket(capacity, outputRate, locker, storage, l.clock, l.logger)

	// Rate limiter returns ErrLimitExhausted, or queues the request.
	res, err := limiter.Limit(ctx)
	if err == nil {
		time.Sleep(res)
	}
	return err
}
