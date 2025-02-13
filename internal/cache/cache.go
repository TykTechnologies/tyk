package cache

import (
	"sync"
	"time"
)

// Cache holds key-value pairs with a TTL.
type Cache struct {
	// expiration (<= 0 means never expire).
	expiration time.Duration

	// janitor holds a clean up goroutine
	janitor *Janitor

	// cache items and protecting mutex
	mu    sync.RWMutex
	items map[string]Item
}

// NewCache creates a new *Cache for storing items with a TTL.
func NewCache(expiration, cleanupInterval time.Duration) *Cache {
	if expiration == 0 {
		expiration = -1
	}

	cache := &Cache{
		items:      make(map[string]Item),
		expiration: expiration,
	}

	if cleanupInterval > 0 {
		// Cache with a cleanup janitor.
		cache.janitor = NewJanitor(cleanupInterval, cache.Cleanup)
	}

	return cache
}

// Close implements an io.Closer; Invoke it to cancel the cleanup goroutine.
func (c *Cache) Close() {
	if c.janitor != nil {
		c.janitor.Close()
		c.janitor = nil
	}
	c.Flush()
}

// Add an item to the cache, replacing any existing item. If the duration is 0,
// the cache's expiration time is used. If it is -1, the item never expires.
func (c *Cache) Set(k string, x any, d time.Duration) {
	var e int64
	if d == 0 {
		d = c.expiration
	}
	if d > 0 {
		e = time.Now().Add(d).UnixNano()
	}
	c.mu.Lock()
	c.items[k] = Item{
		Object:     x,
		Expiration: e,
	}
	c.mu.Unlock()
}

// Get an item from the cache. Returns the item or nil, and a bool indicating
// whether the key was found.
func (c *Cache) Get(k string) (any, bool) {
	c.mu.RLock()

	item, found := c.items[k]
	if !found {
		c.mu.RUnlock()
		return nil, false
	}

	if item.Expiration > 0 {
		if time.Now().UnixNano() > item.Expiration {
			c.mu.RUnlock()
			return nil, false
		}
	}

	c.mu.RUnlock()
	return item.Object, true
}

// Items copies all unexpired items in the cache into a new map and returns it.
func (c *Cache) Items() map[string]Item {
	c.mu.RLock()
	defer c.mu.RUnlock()

	m := make(map[string]Item, len(c.items))

	now := time.Now().UnixNano()
	for k, v := range c.items {
		if v.Expiration > 0 && now > v.Expiration {
			continue
		}
		m[k] = v
	}

	return m
}

// Delete an item from the cache. Does nothing if the key is not in the cache.
func (c *Cache) Delete(k string) {
	c.mu.Lock()
	delete(c.items, k)
	c.mu.Unlock()
}

// Cleanup will delete all expired items from the cache map.
func (c *Cache) Cleanup() {
	now := time.Now().UnixNano()

	c.mu.Lock()
	for k, v := range c.items {
		if v.Expiration > 0 && now > v.Expiration {
			delete(c.items, k)
		}
	}
	c.mu.Unlock()
}

// Count returns the number of items in cache, including expired items.
// Expired items get cleaned up by the janitor periodically.
func (c *Cache) Count() int {
	c.mu.RLock()
	n := len(c.items)
	c.mu.RUnlock()

	return n
}

// Flush deletes all items from the cache.
func (c *Cache) Flush() {
	c.mu.Lock()
	c.items = map[string]Item{}
	c.mu.Unlock()
}
