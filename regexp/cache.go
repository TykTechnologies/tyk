package regexp

import (
	"regexp"
	"time"

	gocache "github.com/TykTechnologies/tyk/internal/cache"
)

const (
	defaultCacheItemTTL         = 60 * time.Second
	defaultCacheCleanupInterval = 5 * time.Minute

	maxKeySize   = 1024
	maxValueSize = 2048
)

type cache struct {
	*gocache.Cache

	isEnabled bool
	ttl       time.Duration
}

func newCache(ttl time.Duration, isEnabled bool) *cache {
	return &cache{
		Cache:     gocache.NewCache(ttl, defaultCacheCleanupInterval),
		isEnabled: isEnabled,
		ttl:       ttl,
	}
}

func (c *cache) enabled() bool {
	return c.isEnabled && c.Cache != nil
}

func (c *cache) add(key string, value interface{}) {
	c.Set(key, value, c.ttl)
}

func (c *cache) getRegexp(key string) (*regexp.Regexp, bool) {
	if val, found := c.Get(key); found {
		return val.(*regexp.Regexp).Copy(), true
	}

	return nil, false
}

func (c *cache) getString(key string) (string, bool) {
	if val, found := c.Get(key); found {
		return val.(string), true
	}

	return "", false
}

func (c *cache) getStrSlice(key string) ([]string, bool) {
	if val, found := c.Get(key); found {
		return val.([]string), true
	}

	return []string{}, false
}

func (c *cache) getStrSliceOfSlices(key string) ([][]string, bool) {
	if val, found := c.Get(key); found {
		return val.([][]string), true
	}

	return [][]string{}, false
}

func (c *cache) getBool(key string) (bool, bool) {
	if val, found := c.Get(key); found {
		return val.(bool), true
	}

	return false, false
}

func (c *cache) reset(ttl time.Duration, isEnabled bool) {
	if c.Cache == nil {
		return
	}

	c.isEnabled = isEnabled
	c.ttl = ttl
	c.Flush()
}
