package regexp

import (
	"regexp"
	"sync/atomic"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

const (
	maxKeySize             = 1024
	maxValueSize           = 2048
	defaultCacheMaxEntries = 5000
)

// cache wraps an expirable.LRU. maxEntries<=0 disables size eviction;
// ttl=0 disables TTL eviction (no sweep goroutine spawned). Both bounds
// are fixed at construction.
type cache struct {
	lru       *expirable.LRU[string, any]
	isEnabled atomic.Bool
}

// evictionReporter records the number of entries evicted from a named cache.
// Implementations must be safe for concurrent use.
type evictionReporter interface {
	record(name string)
}

type noopReporter struct{}

func (noopReporter) record(string) {}

func newCache(ttl time.Duration, isEnabled bool) *cache {
	return newCacheWithSize(ttl, defaultCacheMaxEntries, isEnabled, "", nil)
}

func newCacheWithSize(ttl time.Duration, maxEntries int, isEnabled bool, name string, reporter evictionReporter) *cache {
	if maxEntries < 0 {
		maxEntries = 0
	}
	if reporter == nil {
		reporter = noopReporter{}
	}
	onEvict := func(_ string, _ any) { reporter.record(name) }
	c := &cache{
		lru: expirable.NewLRU[string, any](maxEntries, onEvict, ttl),
	}
	c.isEnabled.Store(isEnabled)
	return c
}

func (c *cache) enabled() bool {
	return c.isEnabled.Load() && c.lru != nil
}

func (c *cache) add(key string, value interface{}) {
	c.lru.Add(key, value)
}

// getRegexp returns the cached *regexp.Regexp shared across all callers.
// Callers must not mutate it (e.g. via Longest()); read-only methods are
// safe for concurrent use since Go 1.12.
func (c *cache) getRegexp(key string) (*regexp.Regexp, bool) {
	if v, ok := c.lru.Get(key); ok {
		return v.(*regexp.Regexp), true
	}

	return nil, false
}

func (c *cache) getString(key string) (string, bool) {
	if v, ok := c.lru.Get(key); ok {
		return v.(string), true
	}

	return "", false
}

func (c *cache) getStrSlice(key string) ([]string, bool) {
	if v, ok := c.lru.Get(key); ok {
		return v.([]string), true
	}

	return []string{}, false
}

func (c *cache) getStrSliceOfSlices(key string) ([][]string, bool) {
	if v, ok := c.lru.Get(key); ok {
		return v.([][]string), true
	}

	return [][]string{}, false
}

func (c *cache) getBool(key string) (bool, bool) {
	if v, ok := c.lru.Get(key); ok {
		return v.(bool), true
	}

	return false, false
}

func (c *cache) reset(isEnabled bool) {
	c.isEnabled.Store(isEnabled)
	c.lru.Purge()
}
