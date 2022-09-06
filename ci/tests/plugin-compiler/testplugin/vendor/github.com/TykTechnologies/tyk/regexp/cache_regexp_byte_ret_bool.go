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

	kb := keyBuilderPool.Get().(*keyBuilder)
	defer keyBuilderPool.Put(kb)
	kb.Reset()

	// generate key, check key size
	nsKey := kb.AppendString(r.String()).AppendBytes(b).UnsafeKey()
	if len(nsKey) > maxKeySize {
		return noCacheFn(b)
	}

	// cache hit
	if res, found := c.getBool(nsKey); found {
		return res
	}

	// cache miss, add to cache
	res := noCacheFn(b)
	c.add(kb.Key(), res)

	return res
}
