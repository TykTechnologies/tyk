package limiter

import (
	"context"
	"time"

	"github.com/TykTechnologies/exp/pkg/limiters"
)

func (l *Limiter) TokenBucket(ctx context.Context, key string, rate float64, per float64) error {
	var (
		storage limiters.TokenBucketStateBackend
		locker  limiters.DistLocker

		capacity  = int64(rate)
		ttl       = time.Duration(per * float64(time.Second))
		raceCheck = false
	)

	rateLimitPrefix := Prefix(l.prefix, key)

	if l.redis != nil {
		locker = l.redisLock(l.prefix)
		storage = limiters.NewTokenBucketRedis(l.redis, rateLimitPrefix, ttl, raceCheck)
	} else {
		locker = l.lock
		storage = limiters.LocalTokenBucket(rateLimitPrefix)
	}

	limiter := limiters.NewTokenBucket(capacity, ttl, locker, storage, l.clock, l.logger)

	// Rate limiter returns a zero duration and a possible ErrLimitExhausted when no tokens are available.
	_, err := limiter.Limit(ctx)
	return err
}
