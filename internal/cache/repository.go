package cache

import (
	"time"
)

// Repository interface is the API signature for an object cache.
type Repository interface {
	Get(string) (interface{}, bool)
	Set(string, interface{}, int64)
	Delete(string)
	Count() int
	Flush()

	Close()
}

var (
	_ Repository = new(MemRepository)
)

// New creates a new cache instance.
func New(defaultExpiration, cleanupInterval int64) *MemRepository {
	var (
		defaultExpirationDuration = time.Duration(defaultExpiration) * time.Second
		cleanupIntervalDuration   = time.Duration(cleanupInterval) * time.Second
	)

	return &MemRepository{
		defaultExpiration: defaultExpiration,
		cleanupInterval:   cleanupInterval,
		cache:             NewCache(defaultExpirationDuration, cleanupIntervalDuration),
	}
}

type MemRepository struct {
	// The underlying cache driver.
	cache *Cache

	// Default expiration interval, in seconds.
	defaultExpiration int64

	// Clean up interval, in seconds.
	cleanupInterval int64
}

// Get retrieves a cache item by key.
func (r *MemRepository) Get(key string) (interface{}, bool) {
	return r.cache.Get(key)
}

// Set writes a cache item with a timeout in seconds. If timeout is zero,
// the default expiration for the MemRepository instance will be used.
func (r *MemRepository) Set(key string, value interface{}, timeout int64) {
	if timeout <= 0 {
		timeout = r.defaultExpiration
	}
	r.cache.Set(key, value, time.Duration(timeout)*time.Second)
}

// Delete cache item by key.
func (r *MemRepository) Delete(key string) {
	r.cache.Delete(key)
}

// Count returns number of items in the cache.
func (r *MemRepository) Count() int {
	return r.cache.Count()
}

// Flush flushes all the items from the cache.
func (r *MemRepository) Flush() {
	r.cache.Flush()
}

// Close will stop background cleanup and clear the cache for garbage collection.
// Close also flushes the data in the cache.
func (r *MemRepository) Close() {
	r.cache.Close()
}

// DefaultExpiration returns default expiration in seconds
func (r *MemRepository) DefaultExpiration() int64 {
	return r.defaultExpiration
}

// CleanupInterval returns cleanup interval in seconds
func (r *MemRepository) CleanupInterval() int64 {
	return r.cleanupInterval
}
