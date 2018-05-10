package regexp

import (
	"regexp"
	"sync"
)

type matchStringCache struct {
	cache   map[string]bool
	cacheMu sync.Mutex
}

func (c *matchStringCache) matchString(r *regexp.Regexp, s string) bool {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	// cache hit
	if matched, ok := c.cache[r.String()+s]; ok {
		return matched
	}

	// cache miss
	realMatched := r.MatchString(s)

	// add to cache
	c.cache[r.String()+s] = realMatched

	return realMatched
}

func (c *matchStringCache) reset() {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	c.cache = map[string]bool{}
}
