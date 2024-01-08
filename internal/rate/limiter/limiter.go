package limiter

import (
	"context"
	"strings"

	"github.com/go-redsync/redsync/v4/redis/goredis/v9"
	"github.com/redis/go-redis/v9"

	"github.com/TykTechnologies/exp/pkg/limiters"
)

var ErrLimitExhausted = limiters.ErrLimitExhausted

type Limiter struct {
	prefix string
	redis  redis.UniversalClient

	lock   limiters.DistLocker
	logger limiters.Logger
	clock  limiters.Clock
}

type LimiterFunc func(ctx context.Context, key string, rate float64, per float64) error

func NewLimiter(prefix string, redis redis.UniversalClient) *Limiter {
	return &Limiter{
		prefix: prefix,
		redis:  redis,
		lock:   limiters.NewLockNoop(),
		logger: limiters.NewStdLogger(),
		clock:  limiters.NewSystemClock(),
	}
}

func (l *Limiter) redisLock(name string) limiters.DistLocker {
	return limiters.NewLockRedis(goredis.NewPool(l.redis), name+"-lock")
}

func Prefix(params ...string) string {
	var res strings.Builder
	var written int

	for _, p := range params {
		if p == "" {
			continue
		}

		if written == 0 {
			res.Write([]byte(p))
			written++
			continue
		}

		res.Write([]byte("-"))
		res.Write([]byte(p))
	}
	return res.String()
}
