package memorycache

import (
	"context"
	"sync"
	"time"
)

// Cache is a synchronised map of items that auto-expire once stale
type Cache struct {
	mutex sync.RWMutex
	ttl   time.Duration
	items map[string]*Item
}

// NewCache is a helper to create instance of the Cache struct.
// The ctx is used to cancel the TTL map cleanup goroutine.
func NewCache(ctx context.Context, duration time.Duration) *Cache {
	cache := &Cache{
		ttl:   duration,
		items: map[string]*Item{},
	}
	go cache.startCleanupTimer(ctx)
	return cache
}

// Set is a thread-safe way to add new items to the map
func (cache *Cache) Set(key string, data *Bucket) {
	cache.mutex.Lock()
	item := &Item{data: data}
	item.touch(cache.ttl)
	cache.items[key] = item
	cache.mutex.Unlock()
}

// Get is a thread-safe way to lookup items
// Every lookup, also touches the item, hence extending it's life
func (cache *Cache) Get(key string) (data *Bucket, found bool) {
	cache.mutex.Lock()
	item, exists := cache.items[key]
	if !exists || item.expired() {
		data = &Bucket{}
		found = false
	} else {
		item.touch(cache.ttl)
		data = item.data
		found = true
	}
	cache.mutex.Unlock()
	return
}

// Count returns the number of items in the cache
// (helpful for tracking memory leaks)
func (cache *Cache) Count() int {
	cache.mutex.RLock()
	count := len(cache.items)
	cache.mutex.RUnlock()
	return count
}

func (cache *Cache) cleanup() {
	cache.mutex.Lock()
	for key, item := range cache.items {
		if item.expired() {
			delete(cache.items, key)
		}
	}
	cache.mutex.Unlock()
}

func (cache *Cache) clear() {
	cache.mutex.Lock()
	cache.items = map[string]*Item{}
	cache.mutex.Unlock()
}

func (cache *Cache) startCleanupTimer(ctx context.Context) {
	interval := cache.ttl
	if interval < time.Second {
		interval = time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			//fmt.Println("Shutting down cleanup timer:", ctx.Err())
			goto done
		case <-ticker.C:
			cache.cleanup()
		}
		break
	}
done:
	cache.clear()
}
