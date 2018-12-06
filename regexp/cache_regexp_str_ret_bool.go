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

	kb := keyBuilderPool.Get().(*keyBuilder)
	defer keyBuilderPool.Put(kb)
	kb.Reset()

	// generate key, check key size
	nsKey := kb.AppendString(r.String()).AppendString(s).UnsafeKey()
	if len(nsKey) > maxKeySize {
		return noCacheFn(s)
	}

	// cache hit
	if res, found := c.getBool(nsKey); found {
		return res
	}

	// cache miss, add to cache
	res := noCacheFn(s)
	c.add(kb.Key(), res)

	return res
}
