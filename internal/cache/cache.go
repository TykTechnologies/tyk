package cache

import (
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
)

// DefaultExpiration is a helper value that uses the repository defaults.
const DefaultExpiration int64 = 0

// Repository interface is the API signature for an object cache.
type Repository interface {
	Get(string) (interface{}, bool)
	Set(string, interface{}, int64)
	Delete(string)
	Count() int
	Flush()
	Close()
}

// New creates a new cache instance.
func New(defaultExpiration, cleanupInterval int64) Repository {
	var (
		defaultExpirationDuration = time.Duration(defaultExpiration) * time.Second
		cleanupIntervalDuration   = time.Duration(cleanupInterval) * time.Second
	)

	return &repository{
		defaultExpiration: defaultExpiration,
		cleanupInterval:   cleanupInterval,
		cache:             cache.New(defaultExpirationDuration, cleanupIntervalDuration),
	}
}

type repository struct {
	mu sync.RWMutex

	// Default expiration interval, in seconds.
	defaultExpiration int64

	// Clean up interval, in seconds.
	cleanupInterval int64

	// The underlying cache driver.
	cache *cache.Cache
}

// Get retrieves a cache item by key.
func (r *repository) Get(key string) (interface{}, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.cache == nil {
		return nil, false
	}

	return r.cache.Get(key)
}

// Set writes a cache item with a timeout in seconds. If timeout is zero,
// the default expiration for the repository instance will be used.
func (r *repository) Set(key string, value interface{}, timeout int64) {
	if timeout <= 0 {
		timeout = r.defaultExpiration
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cache == nil {
		return
	}

	r.cache.Set(key, value, time.Duration(timeout)*time.Second)
}

// Delete cache item by key.
func (r *repository) Delete(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cache == nil {
		return
	}

	r.cache.Delete(key)
}

// Count returns number of items in the cache.
func (r *repository) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.cache == nil {
		return 0
	}

	return r.cache.ItemCount()
}

// Flush flushes all the items from the cache.
func (r *repository) Flush() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cache == nil {
		return
	}

	r.cache.Flush()
}

// Close shuts down the underlying cache safely
func (r *repository) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cache != nil {
		r.cache.Flush()
		r.cache = nil
	}
}
