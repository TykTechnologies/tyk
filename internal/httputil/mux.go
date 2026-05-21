package httputil

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/gorilla/mux"
	"github.com/hashicorp/golang-lru/v2/expirable"

	"github.com/TykTechnologies/tyk/internal/cache"
)

// pathRegexpCache maps mux-style routes to compiled regex source.
// Pure LRU (ttl=0): cold entries are evicted by recency under cap pressure.
var pathRegexpCache atomic.Pointer[expirable.LRU[string, string]]

// prevReporter tracks the EvictionLogger backing the current cache so its
// goroutine can be stopped when ConfigurePathRegexpCache is called again.
var prevReporter atomic.Pointer[cache.EvictionLogger]

func init() {
	pathRegexpCache.Store(expirable.NewLRU[string, string](cache.DefaultLRUMaxEntries, nil, 0))
}

// ConfigurePathRegexpCache replaces the path-regexp cache with one configured by opts.
func ConfigurePathRegexpCache(opts cache.LRUOptions) {
	n := cache.ResolveMaxEntries(opts)

	if old := prevReporter.Swap(nil); old != nil {
		old.Stop()
	}

	var onEvict expirable.EvictCallback[string, string]
	if opts.Log != nil {
		rep := cache.NewEvictionLogger("path-regexp cache", opts.Log)
		rep.Start(cache.DefaultEvictionLogInterval)
		prevReporter.Store(rep)
		onEvict = func(_ string, _ string) { rep.Record("") }
	}

	pathRegexpCache.Store(expirable.NewLRU[string, string](n, onEvict, 0))
}

// apiLandIDsRegex matches mux-style parameters like `{id}`.
var apiLangIDsRegex = regexp.MustCompile(`{([^}]+)}`)

// PreparePathRexep will replace mux-style parameters in input with a compatible regular expression.
// Parameters like `{id}` would be replaced to `([^/]+)`. If the input pattern provides a starting
// or ending delimiters (`^` or `$`), the pattern is returned.
// If prefix is true, and pattern starts with /, the returned pattern prefixes a `^` to the regex.
// No other prefix matches are possible so only `/` to `^/` conversion is considered.
// If suffix is true, the returned pattern suffixes a `$` to the regex.
// If both prefix and suffixes are achieved, an explicit match is made.
func PreparePathRegexp(pattern string, prefix bool, suffix bool) string {
	// Construct cache key from pattern and flags
	key := fmt.Sprintf("%s:%v:%v", pattern, prefix, suffix)
	lru := pathRegexpCache.Load()
	if val, ok := lru.Get(key); ok {
		return val
	}

	// Replace mux named parameters with regex path match.
	if IsMuxTemplate(pattern) {
		pattern = apiLangIDsRegex.ReplaceAllString(pattern, `([^/]+)`)
	}

	// Replace mux wildcard path with a `.*` (match 0 or more characters)
	if strings.Contains(pattern, "/*") {
		pattern = strings.ReplaceAll(pattern, "/*/", "/[^/]+/")
		pattern = strings.ReplaceAll(pattern, "/*", "/.*")
	}

	// Pattern `/users` becomes `^/users`.
	if prefix && strings.HasPrefix(pattern, "/") {
		pattern = "^" + pattern
	}

	// Append $ if necessary to enforce suffix matching.
	// Pattern `/users` becomes `/users$`.
	// Pattern `^/users` becomes `^/users$`.
	if suffix && !strings.HasSuffix(pattern, "$") {
		pattern = pattern + "$"
	}

	// Save cache for following invocations.
	lru.Add(key, pattern)

	return pattern
}

// ValidatePath validates if the path is valid. Returns an error.
func ValidatePath(in string) error {
	router := mux.NewRouter()
	route := router.PathPrefix(in)
	return route.GetError()
}

// IsMuxTemplate determines if a pattern is a mux template by counting the number of opening and closing braces.
func IsMuxTemplate(pattern string) bool {
	openBraces := strings.Count(pattern, "{")
	closeBraces := strings.Count(pattern, "}")
	return openBraces > 0 && openBraces == closeBraces
}

// StripListenPath will strip the listenPath from the passed urlPath.
// If the listenPath contains mux variables, it will trim away the
// matching pattern with a regular expression that mux provides.
func StripListenPath(listenPath, urlPath string) (res string) {
	defer func() {
		if !strings.HasPrefix(res, "/") {
			res = "/" + res
		}
	}()

	res = urlPath

	// early return on the simple case
	if strings.HasPrefix(urlPath, listenPath) {
		res = strings.TrimPrefix(res, listenPath)
		return res
	}

	if !IsMuxTemplate(listenPath) {
		return res
	}

	tmp := new(mux.Route).PathPrefix(listenPath)
	s, err := tmp.GetPathRegexp()
	if err != nil {
		return res
	}

	reg := regexp.MustCompile(s)
	return reg.ReplaceAllString(res, "")
}

// MatchPath matches regexp pattern with request endpoint.
func MatchPath(pattern string, endpoint string) (bool, error) {
	if strings.Trim(pattern, "^$") == "" || endpoint == "" {
		return false, nil
	}
	if pattern == endpoint || pattern == "^"+endpoint+"$" {
		return true, nil
	}

	asRegex, err := regexp.Compile(pattern)
	if err != nil {
		return false, err
	}

	return asRegex.MatchString(endpoint), nil
}

// MatchPaths matches regexp pattern with multiple request URLs endpoint paths.
// It will return true if any of them is correctly matched, with no error.
// If no matches occur, any errors will be retured joined with errors.Join.
func MatchPaths(pattern string, endpoints []string) (bool, error) {
	var errs []error

	for _, endpoint := range endpoints {
		match, err := MatchPath(pattern, endpoint)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if match {
			return true, nil
		}
	}

	return false, errors.Join(errs...)
}
