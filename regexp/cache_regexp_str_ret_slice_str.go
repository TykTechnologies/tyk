package regexp

import (
	"regexp"
	"time"
)

type regexpStrRetSliceStrCache struct {
	*cache
}

// SW-REQ-143
func newRegexpStrRetSliceStrCache(ttl time.Duration, isEnabled bool) *regexpStrRetSliceStrCache {
	return &regexpStrRetSliceStrCache{
		cache: newCache(
			ttl,
			isEnabled,
		),
	}
}

// SW-REQ-143
func (c *regexpStrRetSliceStrCache) do(r *regexp.Regexp, s string, noCacheFn func(s string) []string) []string {
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
	if res, found := c.getStrSlice(nsKey); found {
		return res
	}

	// cache miss, add to cache if value is not too big
	res := noCacheFn(s)
	if len(res) <= maxValueSize {
		c.add(kb.Key(), res)
	}

	return res
}
