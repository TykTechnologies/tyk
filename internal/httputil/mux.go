package httputil

import (
	"strings"

	"github.com/gorilla/mux"

	"github.com/TykTechnologies/tyk/internal/maps"
)

// routeCache holds the raw routes as they are mapped to mux regular expressions.
// e.g. `/foo` becomes `^/foo$` or similar, and parameters get matched and replaced.
var pathRegexpCache = maps.NewStringMap()

// GetPathRegexp will convert a mux route url to a regular expression string.
// The results for subsequent invocations with the same parameters are cached.
func GetPathRegexp(pattern string) (string, error) {
	val, ok := pathRegexpCache.Get(pattern)
	if ok {
		return val, nil
	}

	if IsMuxTemplate(pattern) {
		dummyRouter := mux.NewRouter()
		route := dummyRouter.PathPrefix(pattern)
		result, err := route.GetPathRegexp()
		if err != nil {
			return "", err
		}

		pathRegexpCache.Set(pattern, result)
		return result, nil
	}

	if strings.HasPrefix(pattern, "/") {
		return "^" + pattern, nil
	}
	return "^.*" + pattern, nil
}

// IsMuxTemplate determines if a pattern is a mux template by counting the number of opening and closing braces.
func IsMuxTemplate(pattern string) bool {
	openBraces := strings.Count(pattern, "{")
	closeBraces := strings.Count(pattern, "}")
	return openBraces > 0 && openBraces == closeBraces
}
