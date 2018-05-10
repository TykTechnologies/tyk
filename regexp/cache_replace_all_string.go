package regexp

import (
	"regexp"
	"sync"
)

type replaceAllStringCache struct {
	cache   map[string]string
	cacheMu sync.Mutex
}

func (c *replaceAllStringCache) replaceAllString(r *regexp.Regexp, src, repl string) string {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	// cache hit
	if hitRes, ok := c.cache[r.String()+src+repl]; ok {
		return hitRes
	}

	// cache miss
	res := r.ReplaceAllString(src, repl)

	// add to cache
	c.cache[r.String()+src+repl] = res

	return res
}

func (c *replaceAllStringCache) reset() {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	c.cache = map[string]string{}
}
