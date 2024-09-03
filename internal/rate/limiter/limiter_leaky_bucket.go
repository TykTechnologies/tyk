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

<<<<<<< HEAD
	rateLimitPrefix := Prefix(l.prefix, key)

	if l.redis != nil {
		locker = l.redisLock(l.prefix)
		storage = limiters.NewLeakyBucketRedis(l.redis, rateLimitPrefix, ttl, raceCheck)
	} else {
		locker = l.lock
		storage = limiters.LocalLeakyBucket(rateLimitPrefix)
=======
	locker = l.Locker(key)
	if l.redis != nil {
		storage = limiters.NewLeakyBucketRedis(l.redis, key, ttl, raceCheck)
	} else {
		storage = limiters.LocalLeakyBucket(key)
>>>>>>> 36509786e... [TT-12452] Clear up quota gated with a distributed redis lock (#6448)
	}

	limiter := limiters.NewLeakyBucket(capacity, outputRate, locker, storage, l.clock, l.logger)

	// Rate limiter returns ErrLimitExhausted, or queues the request.
	res, err := limiter.Limit(ctx)
	if err == nil {
		time.Sleep(res)
	}
	return err
}
