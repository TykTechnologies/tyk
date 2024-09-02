package httputil

import (
	"errors"
	"regexp"
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
	if strings.HasPrefix(pattern, "^") {
		return pattern, nil
	}
	return "^.*" + pattern, nil
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

// MatchEndpoint matches pattern with request endpoint.
func MatchEndpoint(pattern string, endpoint string) (bool, error) {
	if pattern == endpoint {
		return true, nil
	}

	if pattern == "" {
		return false, nil
	}

	clean, err := GetPathRegexp(pattern)
	if err != nil {
		return false, err
	}

	asRegex, err := regexp.Compile(clean)
	if err != nil {
		return false, err
	}

	return asRegex.MatchString(endpoint), nil
}

// MatchEndpoints matches pattern with multiple request URLs endpoint paths.
// It will return true if any of them is correctly matched, with no error.
// If no matches occur, any errors will be retured joined with errors.Join.
func MatchEndpoints(pattern string, endpoints []string) (bool, error) {
	var errs []error

	for _, endpoint := range endpoints {
		match, err := MatchEndpoint(pattern, endpoint)
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
