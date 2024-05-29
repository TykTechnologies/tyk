package rate

import (
	"context"
	"fmt"

	"github.com/TykTechnologies/exp/pkg/limiters"
	"github.com/TykTechnologies/tyk/internal/redis"
)

// AllowanceRepository is the interface for accessing rate limit allowance.
type AllowanceRepository interface {
	fmt.Stringer

	Locker(name string) limiters.DistLocker

	Get(ctx context.Context, key string) (*Allowance, error)
	Set(ctx context.Context, key string, allowance *Allowance) error
}

// SmoothingFn is the signature for a rate limiter decision based on rate.
type SmoothingFn func(ctx context.Context, key string, currentRate int64, maxAllowedRate int64) bool

// RedisClientProvider is a hidden storage API, providing us with a redis.UniversalClient.
type RedisClientProvider interface {
	// Client returns the redis.UniversalClient or an error if not available.
	Client() (redis.UniversalClient, error)
}
