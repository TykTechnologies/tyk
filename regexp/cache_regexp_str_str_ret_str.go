package regexp

import (
	"regexp"
	"time"
)

type regexpStrStrRetStrCache struct {
	*cache
}

func newRegexpStrStrRetStrCache(ttl time.Duration, isEnabled bool) *regexpStrStrRetStrCache {
	return &regexpStrStrRetStrCache{
		cache: newCache(
			ttl,
			isEnabled,
		),
	}
}

func (c *regexpStrStrRetStrCache) do(r *regexp.Regexp, src string, repl string, noCacheFn func(string, string) string) string {
	// return if cache is not enabled
	if !c.enabled() {
		return noCacheFn(src, repl)
	}

	key := r.String() + src + repl

	// cache hit
	if res, found := c.getString(key); found {
		return res
	}

	// cache miss, add to cache
	res := noCacheFn(src, repl)
	c.add(key, res)

	return res
}
