package regexp

import (
	"fmt"
	"regexp"
	"time"
)

type regexpStrFuncRetStrCache struct {
	*cache
}

func newRegexpStrFuncRetStrCache(ttl time.Duration, isEnabled bool) *regexpStrFuncRetStrCache {
	return &regexpStrFuncRetStrCache{
		cache: newCache(
			ttl,
			isEnabled,
		),
	}
}

func (c *regexpStrFuncRetStrCache) do(r *regexp.Regexp, src string, repl func(string) string, noCacheFn func(string, func(string) string) string) string {
	// return if cache is not enabled
	if !c.enabled() {
		return noCacheFn(src, repl)
	}

	key := r.String() + src + fmt.Sprintf("%p", repl)

	// cache hit
	if res, found := c.getString(key); found {
		return res
	}

	// cache miss, add to cache
	res := noCacheFn(src, repl)
	c.add(key, res)

	return res
}
