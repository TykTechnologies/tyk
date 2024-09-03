package limiter

import (
	"context"
	"strings"

	"github.com/TykTechnologies/exp/pkg/limiters"

	"github.com/TykTechnologies/tyk/internal/redis"
)

var ErrLimitExhausted = limiters.ErrLimitExhausted

type Limiter struct {
	prefix string
	redis  redis.UniversalClient

	locker limiters.DistLocker
	logger limiters.Logger
	clock  limiters.Clock
}

type LimiterFunc func(ctx context.Context, key string, rate float64, per float64) error

<<<<<<< HEAD
func NewLimiter(prefix string, redis redis.UniversalClient) *Limiter {
=======
// NewLimiter creates a new limiter object. It holds the redis client and the
// default non-distributed locks, logger, and a clock for supporting tests.
func NewLimiter(redis redis.UniversalClient) *Limiter {
>>>>>>> 36509786e... [TT-12452] Clear up quota gated with a distributed redis lock (#6448)
	return &Limiter{
		prefix: prefix,
		redis:  redis,
		locker: limiters.NewLockNoop(),
		logger: limiters.NewStdLogger(),
		clock:  limiters.NewSystemClock(),
	}
}

// Locker will ensure a distributed lock with redis, using redsync for a key.
// If redis is not in use, fallback is done to use the default locker.
func (l *Limiter) Locker(name string) limiters.DistLocker {
	if l.redis != nil {
		return limiters.NewLockRedis(redis.NewPool(l.redis), name+"-lock")
	}
	return l.locker
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
