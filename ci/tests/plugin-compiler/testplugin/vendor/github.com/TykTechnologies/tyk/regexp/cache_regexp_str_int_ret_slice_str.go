package regexp

import (
	"regexp"
	"time"
)

type regexpStrIntRetSliceStrCache struct {
	*cache
}

func newRegexpStrIntRetSliceStrCache(ttl time.Duration, isEnabled bool) *regexpStrIntRetSliceStrCache {
	return &regexpStrIntRetSliceStrCache{
		cache: newCache(
			ttl,
			isEnabled,
		),
	}
}

func (c *regexpStrIntRetSliceStrCache) do(r *regexp.Regexp, s string, n int, noCacheFn func(s string, n int) []string) []string {
	// return if cache is not enabled
	if !c.enabled() {
		return noCacheFn(s, n)
	}

	kb := keyBuilderPool.Get().(*keyBuilder)
	defer keyBuilderPool.Put(kb)
	kb.Reset()

	// generate key, check key size
	nsKey := kb.AppendString(r.String()).AppendString(s).AppendInt(n).UnsafeKey()
	if len(nsKey) > maxKeySize {
		return noCacheFn(s, n)
	}

	// cache hit
	if res, found := c.getStrSlice(nsKey); found {
		return res
	}

	// cache miss, add to cache if value is not too big
	res := noCacheFn(s, n)
	if len(res) > maxValueSize {
		return res
	}

	c.add(kb.Key(), res)

	return res
}
