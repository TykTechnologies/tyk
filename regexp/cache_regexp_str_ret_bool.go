package regexp

import (
	"regexp"
	"time"
)

type regexpStrRetBoolCache struct {
	*cache
}

func newRegexpStrRetBoolCache(ttl time.Duration, isEnabled bool) *regexpStrRetBoolCache {
	return &regexpStrRetBoolCache{
		cache: newCache(
			ttl,
			isEnabled,
		),
	}
}

func (c *regexpStrRetBoolCache) do(r *regexp.Regexp, s string, noCacheFn func(string) bool) bool {
	// return if cache is not enabled
	if !c.enabled() {
		return noCacheFn(s)
	}

	// generate key, check key size
	key := r.String() + s
	if len(key) > maxKeySize {
		return noCacheFn(s)
	}

	// cache hit
	if res, found := c.getBool(key); found {
		return res
	}

	// cache miss, add to cache
	res := noCacheFn(s)
	c.add(key, res)

	return res
}
