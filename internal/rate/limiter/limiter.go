package limiter

import (
	"context"

	"github.com/TykTechnologies/exp/pkg/limiters"

	"github.com/TykTechnologies/tyk/internal/redis"
)

var ErrLimitExhausted = limiters.ErrLimitExhausted

type Limiter struct {
	redis redis.UniversalClient

	lock   limiters.DistLocker
	logger limiters.Logger
	clock  limiters.Clock
}

type LimiterFunc func(ctx context.Context, key string, rate float64, per float64) error

func NewLimiter(redis redis.UniversalClient) *Limiter {
	return &Limiter{
		redis:  redis,
		lock:   limiters.NewLockNoop(),
		logger: limiters.NewStdLogger(),
		clock:  limiters.NewSystemClock(),
	}
}

func (l *Limiter) redisLock(name string) limiters.DistLocker {
	return limiters.NewLockRedis(redis.NewPool(l.redis), name+"-lock")
}
