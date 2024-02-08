package cache

import (
	"time"

	"github.com/pmylund/go-cache"
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
	// Default expiration interval, in seconds.
	defaultExpiration int64

	// Clean up interval, in seconds.
	cleanupInterval int64

	// The underlying cache driver.
	cache *cache.Cache
}

// Get retrieves a cache item by key.
func (r *repository) Get(key string) (interface{}, bool) {
	return r.cache.Get(key)
}

// Set writes a cache item with a timeout in seconds. If timeout is zero,
// the default expiration for the repository instance will be used.
func (r *repository) Set(key string, value interface{}, timeout int64) {
	if timeout <= 0 {
		timeout = r.defaultExpiration
	}
	r.cache.Set(key, value, time.Duration(timeout)*time.Second)
}

// Delete cache item by key.
func (r *repository) Delete(key string) {
	r.cache.Delete(key)
}

// Count returns number of items in the cache.
func (r *repository) Count() int {
	return r.cache.ItemCount()
}

// Flush flushes all the items from the cache.
func (r *repository) Flush() {
	r.cache.Flush()
}
