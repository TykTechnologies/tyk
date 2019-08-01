package regexp

import (
	"regexp"
	"time"
)

type regexpByteRetBoolCache struct {
	*cache
}

func newRegexpByteRetBoolCache(ttl time.Duration, isEnabled bool) *regexpByteRetBoolCache {
	return &regexpByteRetBoolCache{
		cache: newCache(
			ttl,
			isEnabled,
		),
	}
}

func (c *regexpByteRetBoolCache) do(r *regexp.Regexp, b []byte, noCacheFn func([]byte) bool) bool {
	// return if cache is not enabled
	if !c.enabled() {
		return noCacheFn(b)
	}

	// generate key, check key size
	key := r.String() + string(b)
	if len(key) > maxKeySize {
		return noCacheFn(b)
	}

	// cache hit
	if res, found := c.getBool(key); found {
		return res
	}

	// cache miss, add to cache
	res := noCacheFn(b)
	c.add(key, res)

	return res
}
