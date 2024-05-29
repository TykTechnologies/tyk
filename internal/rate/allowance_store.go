package rate

import (
	"context"

	"github.com/TykTechnologies/exp/pkg/limiters"
	"github.com/TykTechnologies/tyk/internal/redis"
)

// AllowanceStore implements AllowanceRepository.
type AllowanceStore struct {
	redis redis.UniversalClient
}

// NewAllowanceStore will return a new instance of *AllowanceStore.
func NewAllowanceStore(redis redis.UniversalClient) *AllowanceStore {
	return &AllowanceStore{
		redis: redis,
	}
}

// Locker returns a distributed locker, similar to a mutex.
func (d *AllowanceStore) Locker(key string) limiters.DistLocker {
	// Handle distributed lock for the write
	return limiters.NewLockRedis(redis.NewPool(d.redis), Prefix(key, "lock"))
}

// Get retrieves and decodes an Allowance value from storage.
func (d *AllowanceStore) Get(ctx context.Context, key string) (*Allowance, error) {
	hval, err := d.redis.HGetAll(ctx, Prefix(key, "allowance")).Result()
	if err != nil {
		return nil, err
	}

	return NewAllowanceFromMap(hval), nil
}

// Set will write the passed Allowance value to storage.
func (d *AllowanceStore) Set(ctx context.Context, key string, allowance *Allowance) error {
	return d.redis.HSet(ctx, Prefix(key, "allowance"), allowance.Map()).Err()
}

// Compile time check that *AllowanceStore implements AllowanceRepository.
var _ AllowanceRepository = &AllowanceStore{}
