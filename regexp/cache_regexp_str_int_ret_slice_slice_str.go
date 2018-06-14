package regexp

import (
	"regexp"
	"strconv"
	"time"
)

type regexpStrIntRetSliceSliceStrCache struct {
	*cache
}

func newRegexpStrIntRetSliceSliceStrCache(ttl time.Duration, isEnabled bool) *regexpStrIntRetSliceSliceStrCache {
	return &regexpStrIntRetSliceSliceStrCache{
		cache: newCache(
			ttl,
			isEnabled,
		),
	}
}

func (c *regexpStrIntRetSliceSliceStrCache) do(r *regexp.Regexp, s string, n int, noCacheFn func(s string, n int) [][]string) [][]string {
	// return if cache is not enabled
	if !c.enabled() {
		return noCacheFn(s, n)
	}

	// generate key, check key size
	key := r.String() + s + strconv.Itoa(n)
	if len(key) > maxKeySize {
		return noCacheFn(s, n)
	}

	// cache hit
	if res, found := c.getStrSliceOfSlices(key); found {
		return res
	}

	// cache miss, add to cache if value is not too big
	res := noCacheFn(s, n)
	if len(res) > maxValueSize {
		return res
	}

	c.add(key, res)

	return res
}
