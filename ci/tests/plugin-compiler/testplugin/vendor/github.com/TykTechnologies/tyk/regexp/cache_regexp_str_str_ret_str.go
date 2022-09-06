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

	kb := keyBuilderPool.Get().(*keyBuilder)
	defer keyBuilderPool.Put(kb)
	kb.Reset()

	// generate key, check key size
	nsKey := kb.AppendString(r.String()).AppendString(src).AppendString(repl).UnsafeKey()
	if len(nsKey) > maxKeySize {
		return noCacheFn(src, repl)
	}

	// cache hit
	if res, found := c.getString(nsKey); found {
		return res
	}

	// cache miss, add to cache if value is not too big
	res := noCacheFn(src, repl)
	if len(res) > maxValueSize {
		return res
	}

	c.add(kb.Key(), res)

	return res
}
