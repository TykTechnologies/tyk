package httputil

// PathRegexpCacheLen returns the current entry count of the path-regexp
// cache. Test-only: defined in *_test.go so it is invisible to
// production builds.
func PathRegexpCacheLen() int {
	if lru := pathRegexpCache.Load(); lru != nil {
		return lru.Len()
	}
	return 0
}
