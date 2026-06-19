package limiter

import (
	"context"
	"time"

	"github.com/TykTechnologies/exp/pkg/limiters"

	"github.com/TykTechnologies/tyk/internal/redis"
)

var ErrLimitExhausted = limiters.ErrLimitExhausted

// SW-REQ-018
type Limiter struct {
	redis redis.UniversalClient

	locker limiters.DistLocker
	logger limiters.Logger
	clock  limiters.Clock
}

// SW-REQ-018
type Func func(ctx context.Context, key string, rate float64, per float64) (ttl time.Duration, err error)

// SW-REQ-018
// NewLimiter creates a new limiter object. It holds the redis client and the
// default non-distributed locks, logger, and a clock for supporting tests.
func NewLimiter(redis redis.UniversalClient) *Limiter {
	return &Limiter{
		redis:  redis,
		locker: limiters.NewLockNoop(),
		logger: limiters.NewStdLogger(),
		clock:  limiters.NewSystemClock(),
	}
}

// SW-REQ-018
// Locker will ensure a distributed lock with redis, using redsync for a key.
// If redis is not in use, fallback is done to use the default locker.
func (l *Limiter) Locker(name string) limiters.DistLocker {
	if l.redis != nil {
		return limiters.NewLockRedis(redis.NewPool(l.redis), name+"-lock")
	}
	return l.locker
}
