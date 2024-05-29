package rate

import (
	"context"
	"encoding/json"
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
	cache   map[string][]byte

	stats struct {
		set       int64
		setErrors int64

		get       int64
		getCached int64
		getErrors int64

		locker int64
	}
}

// NewAllowanceStore will return a new instance of *AllowanceStore.
func NewAllowanceStore(redis redis.UniversalClient) *AllowanceStore {
	return &AllowanceStore{
		redis: redis,
		cache: make(map[string][]byte),
	}
}

// String will return the stats for the AllowanceStore.
func (s *AllowanceStore) String() string {
	var (
		locker    = atomic.LoadInt64(&s.stats.locker)
		set       = atomic.LoadInt64(&s.stats.set)
		setErrors = atomic.LoadInt64(&s.stats.setErrors)
		get       = atomic.LoadInt64(&s.stats.get)
		getCached = atomic.LoadInt64(&s.stats.getCached)
		getErrors = atomic.LoadInt64(&s.stats.getErrors)
	)
	return fmt.Sprintf("locker=%d set=%d setErrors=%d get=%d getCached=%d getErrors=%d", locker, set, setErrors, get, getCached, getErrors)
}

func (s *AllowanceStore) get(key string) *Allowance {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	if cached, ok := s.cache[key]; ok {
		allowance := &Allowance{}
		// We have control over the type, marshalling must not fail.
		_ = json.Unmarshal(cached, allowance)
		return allowance
	}
	return nil
}

func (s *AllowanceStore) set(key string, allowance *Allowance) {
	// We have control over the type, marshalling must not fail.
	b, _ := json.Marshal(allowance)

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	s.cache[key] = b
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
		atomic.AddInt64(&s.stats.getErrors, 1)
		return nil, err
	}

	result = NewAllowanceFromMap(hval)

	s.set(key, result)

	return result, nil
}

// Set will write the passed Allowance value to storage.
func (s *AllowanceStore) Set(ctx context.Context, key string, allowance *Allowance) error {
	allowanceKey := Prefix(key, "allowance")

	atomic.AddInt64(&s.stats.set, 1)
	err := s.redis.HSet(ctx, allowanceKey, allowance.Map()).Err()
	if err != nil {
		atomic.AddInt64(&s.stats.setErrors, 1)
	}
	s.redis.Expire(ctx, allowanceKey, 2*allowance.GetDelay())
	s.set(key, allowance)
	return err
}

// Compile time check that *AllowanceStore implements AllowanceRepository.
var _ AllowanceRepository = &AllowanceStore{}
