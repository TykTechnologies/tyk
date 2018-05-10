package regexp

import (
	"regexp"
	"sync"
)

type compileCache struct {
	cache   map[string]*regexp.Regexp
	cacheMu sync.Mutex
}

func (c *compileCache) compile(expr string) (*Regexp, error) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	// cache hit
	if realRegexpHit, ok := c.cache[expr]; ok {
		return &Regexp{
				realRegexpHit.Copy(),
				true,
			},
			nil
	}

	// cache miss
	realRegexp, err := regexp.Compile(expr)
	if err != nil {
		return nil, err
	}

	// add to cache
	c.cache[expr] = realRegexp

	// return ready to use copy
	return &Regexp{
			realRegexp.Copy(),
			false,
		},
		nil
}

func (c *compileCache) reset() {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	c.cache = map[string]*regexp.Regexp{}
}
