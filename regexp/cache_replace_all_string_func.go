package regexp

import (
	"fmt"
	"regexp"
	"sync"
)

type replaceAllStringFuncCache struct {
	cache   map[string]string
	cacheMu sync.Mutex
}

func (c *replaceAllStringFuncCache) replaceAllStringFunc(r *regexp.Regexp, src string, repl func(string) string) string {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	// cache hit
	if hitRes, ok := c.cache[r.String()+src+fmt.Sprintf("%p", repl)]; ok {
		return hitRes
	}

	// cache miss
	res := r.ReplaceAllStringFunc(src, repl)

	// add to cache
	c.cache[r.String()+src+fmt.Sprintf("%p", repl)] = res

	return res
}
