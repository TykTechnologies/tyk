package httputil

import (
	"github.com/gorilla/mux"

	"github.com/TykTechnologies/tyk/internal/maps"
)

// routeCache holds the raw routes as they are mapped to mux regular expressions.
// e.g. `/foo` becomes `^/foo$` or similar, and parameters get matched and replaced.
var pathRegexpCache = maps.NewStringMap()

// RouteRegexString will convert a mux route url to a regular expression string.
// The results for subsequent invocations with the same parameters are cached.
func GetPathRegexp(pattern string) (string, error) {
	val, ok := pathRegexpCache.Get(pattern)
	if ok {
		return val, nil
	}

	dummyRouter := mux.NewRouter()
	route := dummyRouter.PathPrefix(pattern)
	result, err := route.GetPathRegexp()
	if err != nil {
		return "", err
	}

	pathRegexpCache.Set(pattern, result)

	return result, nil
}
