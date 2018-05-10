package regexp

import (
	"regexp"
	"sync"
)

type matchCache struct {
	cache   map[string]bool
	cacheMu sync.Mutex
}

func (c *matchCache) match(r *regexp.Regexp, b []byte) bool {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	// cache hit
	if matched, ok := c.cache[r.String()+string(b)]; ok {
		return matched
	}

	// cache miss
	realMatched := r.Match(b)

	// add to cache
	c.cache[r.String()+string(b)] = realMatched

	return realMatched
}

func (c *matchCache) reset() {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	c.cache = map[string]bool{}
}
