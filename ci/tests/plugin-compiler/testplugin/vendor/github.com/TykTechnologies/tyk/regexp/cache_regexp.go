package regexp

import (
	"regexp"
	"time"
)

type regexpCache struct {
	*cache
	noCacheFunc func(string) (*regexp.Regexp, error)
}

func newRegexpCache(ttl time.Duration, isEnabled bool, fn func(string) (*regexp.Regexp, error)) *regexpCache {
	return &regexpCache{
		cache: newCache(
			ttl,
			isEnabled,
		),
		noCacheFunc: fn,
	}
}

func (c *regexpCache) doNoCacheFunc(str string) (*Regexp, error) {
	rx, err := c.noCacheFunc(str)
	if err != nil {
		return nil, err
	}

	return &Regexp{
			rx,
			false,
		},
		nil
}

func (c *regexpCache) do(str string) (*Regexp, error) {
	// return if cache is not enabled
	if !c.enabled() {
		return c.doNoCacheFunc(str)
	}

	// cache hit
	if rx, found := c.getRegexp(str); found {
		return &Regexp{
				rx,
				true,
			},
			nil
	}

	// cache miss, add to cache
	regExp, err := c.doNoCacheFunc(str)
	if err != nil {
		return nil, err
	}
	c.add(str, regExp.Regexp)

	return regExp, nil
}
