package regexp

import (
	"regexp"
	"sync/atomic"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"

	internalcache "github.com/TykTechnologies/tyk/internal/cache"
)

const (
	maxKeySize             = 1024
	maxValueSize           = 2048
	defaultCacheMaxEntries = internalcache.DefaultLRUMaxEntries
)

// cache wraps an expirable.LRU.
type cache struct {
	lru       *expirable.LRU[string, any]
	isEnabled atomic.Bool
}

// evictionReporter records the number of entries evicted from a named cache.
// Implementations must be safe for concurrent use.
type evictionReporter interface {
	Record(bucket string)
}

type noopReporter struct{}

// Record satisfies evictionReporter when reporting is disabled.
func (noopReporter) Record(string) {}

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

	// Only wire the reporter when a size bound is in effect. maxEntries=0 means
	// unbounded (LRU eviction disabled); the only callbacks that would fire are
	// TTL expirations — normal cache aging, not size pressure worth logging.
	var onEvict expirable.EvictCallback[string, any]
	if maxEntries > 0 {
		onEvict = func(_ string, _ any) { reporter.Record(name) }
	}
	c := &cache{
		lru: expirable.NewLRU[string, any](maxEntries, onEvict, ttl),
	}

	c.isEnabled.Store(isEnabled)

	return c
}

func (c *cache) enabled() bool {
	return c.isEnabled.Load()
}

func (c *cache) add(key string, value any) {
	c.lru.Add(key, value)
}

// getRegexp returns the cached *regexp.Regexp shared across all callers.
// Callers must not mutate it (e.g. via Longest()); read-only methods are
// safe for concurrent use since Go 1.12.
func (c *cache) getRegexp(key string) (*regexp.Regexp, bool) {
	if v, ok := c.lru.Get(key); ok {
		if r, ok := v.(*regexp.Regexp); ok {
			return r, true
		}
	}

	return nil, false
}

func (c *cache) getString(key string) (string, bool) {
	if v, ok := c.lru.Get(key); ok {
		if s, ok := v.(string); ok {
			return s, true
		}
	}

	return "", false
}

func (c *cache) getStrSlice(key string) ([]string, bool) {
	if v, ok := c.lru.Get(key); ok {
		if s, ok := v.([]string); ok {
			return s, true
		}
	}

	return []string{}, false
}

func (c *cache) getStrSliceOfSlices(key string) ([][]string, bool) {
	if v, ok := c.lru.Get(key); ok {
		if s, ok := v.([][]string); ok {
			return s, true
		}
	}

	return [][]string{}, false
}

func (c *cache) getBool(key string) (bool, bool) {
	if v, ok := c.lru.Get(key); ok {
		if b, ok := v.(bool); ok {
			return b, true
		}
	}

	return false, false
}

func (c *cache) reset(isEnabled bool) {
	c.isEnabled.Store(isEnabled)
	c.lru.Purge()
}
