package rate

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/TykTechnologies/exp/pkg/limiters"
	"github.com/TykTechnologies/tyk/internal/redis"
)

// AllowanceStore implements AllowanceRepository.
type AllowanceStore struct {
	redis redis.UniversalClient

	cacheMu sync.RWMutex
	cache   map[string]*Allowance

	stats struct {
		set       int64
		get       int64
		getCached int64
		locker    int64
	}
}

// NewAllowanceStore will return a new instance of *AllowanceStore.
func NewAllowanceStore(redis redis.UniversalClient) *AllowanceStore {
	return &AllowanceStore{
		redis: redis,
		cache: map[string]*Allowance{},
	}
}

// String will return the stats for the AllowanceStore.
func (s *AllowanceStore) String() string {
	var (
		locker    = atomic.LoadInt64(&s.stats.locker)
		set       = atomic.LoadInt64(&s.stats.set)
		get       = atomic.LoadInt64(&s.stats.get)
		getCached = atomic.LoadInt64(&s.stats.getCached)
	)
	return fmt.Sprintf("locker=%d set=%d get=%d getCached=%d", locker, set, get, getCached)
}

func (s *AllowanceStore) get(key string) *Allowance {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	cached, _ := s.cache[key]
	if cached != nil && cached.Expired() {
		delete(s.cache, key)
		return nil
	}
	return cached
}

func (s *AllowanceStore) set(key string, allowance *Allowance) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	s.cache[key] = allowance
}

// Locker returns a distributed locker, similar to a mutex.
func (s *AllowanceStore) Locker(key string) limiters.DistLocker {
	atomic.AddInt64(&s.stats.locker, 1)
	// Handle distributed lock for the write
	return limiters.NewLockRedis(redis.NewPool(s.redis), Prefix(key, "lock"))
}

// Get retrieves and decodes an Allowance value from storage.
func (s *AllowanceStore) Get(ctx context.Context, key string) (*Allowance, error) {
	atomic.AddInt64(&s.stats.get, 1)

	result := s.get(key)
	if result != nil {
		atomic.AddInt64(&s.stats.getCached, 1)
		return result, nil
	}

	hval, err := s.redis.HGetAll(ctx, Prefix(key, "allowance")).Result()
	if err != nil {
		return nil, err
	}

	result = NewAllowanceFromMap(hval)

	s.set(key, result)

	return result, nil
}

// Set will write the passed Allowance value to storage.
func (s *AllowanceStore) Set(ctx context.Context, key string, allowance *Allowance) error {
	atomic.AddInt64(&s.stats.set, 1)
	return s.redis.HSet(ctx, Prefix(key, "allowance"), allowance.Map()).Err()
}

// Compile time check that *AllowanceStore implements AllowanceRepository.
var _ AllowanceRepository = &AllowanceStore{}
