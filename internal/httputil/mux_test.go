package httputil_test

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/httputil"
)

func pathRegexp(tb testing.TB, in string, want string) string {
	tb.Helper()

	res, err := httputil.GetPathRegexp(in)
	assert.NoError(tb, err)
	if want != "" {
		assert.Equal(tb, want, res)
	}
	return res
}

func preparePathRegexp(tb testing.TB, in string, want string) string {
	tb.Helper()

	res := httputil.PreparePathRegexp(in, true, false)
	assert.Equal(tb, want, res)
	return res
}

func TestGetPathRegexp(t *testing.T) {
	tests := map[string]string{
		"/users*.":                             "^/users*.",
		"/users":                               "^/users",
		"users":                                "^.*users",
		"^/test/users":                         "^/test/users",
		"/users$":                              "^/users$",
		"/users/.*":                            "^/users/.*",
		"/users/{id}":                          "^/users/(?P<v0>[^/]+)",
		"/users/{id}$":                         "^/users/(?P<v0>[^/]+)$",
		"/users/{id}/profile/{type:[a-zA-Z]+}": "^/users/(?P<v0>[^/]+)/profile/(?P<v1>[a-zA-Z]+)",
		"/static/{path}/assets/{file}":         "^/static/(?P<v0>[^/]+)/assets/(?P<v1>[^/]+)",
		"/items/{itemID:[0-9]+}/details/{detail}": "^/items/(?P<v0>[0-9]+)/details/(?P<v1>[^/]+)",
	}

	for k, v := range tests {
		pathRegexp(t, k, v)
	}
}

func TestPreparePathRegexp(t *testing.T) {
	tests := map[string]string{
		"/users*.":                             "^/users*.",
		"/users":                               "^/users",
		"users":                                "users",
		"^/test/users":                         "^/test/users",
		"/users$":                              "^/users$",
		"/users/.*":                            "^/users/.*",
		"/users/{id}":                          "^/users/([^/]+)",
		"/users/{id}$":                         "^/users/([^/]+)$",
		"/users/{id}/profile/{type:[a-zA-Z]+}": "^/users/([^/]+)/profile/([^/]+)",
		"/static/{path}/assets/{file}":         "^/static/([^/]+)/assets/([^/]+)",
		"/items/{itemID:[0-9]+}/details/{detail}": "^/items/([^/]+)/details/([^/]+)",
	}

	for k, v := range tests {
		preparePathRegexp(t, k, v)
	}
}

func TestGetPathRegexpWithRegexCompile(t *testing.T) {
	pattern := pathRegexp(t, "/api/v1/users/{userId}/roles/{roleId}", "")

	matched, err := regexp.MatchString(pattern, "/api/v1/users/10512/roles/32587")
	assert.NoError(t, err)
	assert.True(t, matched, "The URL should match the pattern")
}

func TestStripListenPath(t *testing.T) {
	assert.Equal(t, "/get", httputil.StripListenPath("/listen", "/listen/get"))
	assert.Equal(t, "/get", httputil.StripListenPath("/listen/", "/listen/get"))
	assert.Equal(t, "/get", httputil.StripListenPath("listen", "listen/get"))
	assert.Equal(t, "/get", httputil.StripListenPath("listen/", "listen/get"))
	assert.Equal(t, "/", httputil.StripListenPath("/listen/", "/listen/"))
	assert.Equal(t, "/", httputil.StripListenPath("/listen", "/listen"))
	assert.Equal(t, "/", httputil.StripListenPath("listen/", ""))

	assert.Equal(t, "/get", httputil.StripListenPath("/{_:.*}/post/", "/listen/post/get"))
	assert.Equal(t, "/get", httputil.StripListenPath("/{_:.*}/", "/listen/get"))
	assert.Equal(t, "/get", httputil.StripListenPath("/pre/{_:.*}/", "/pre/listen/get"))
	assert.Equal(t, "/", httputil.StripListenPath("/{_:.*}", "/listen"))
	assert.Equal(t, "/get", httputil.StripListenPath("/{myPattern:foo|bar}", "/foo/get"))
	assert.Equal(t, "/anything/get", httputil.StripListenPath("/{myPattern:foo|bar}", "/anything/get"))
}

func TestMatchPaths(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		endpoint string
		match    bool
		isErr    bool
	}{
		{
			name:     "exact endpoints",
			pattern:  "/api/v1/users",
			endpoint: "/api/v1/users",
			match:    true,
			isErr:    false,
		},
		{
			name:     "non matching concrete endpoints",
			pattern:  "/api/v1/users",
			endpoint: "/api/v1/admin",
			match:    false,
			isErr:    false,
		},
		{
			name:     "regexp match",
			pattern:  "/api/v1/user/\\d+",
			endpoint: "/api/v1/user/123",
			match:    true,
			isErr:    false,
		},
		{
			name:     "regexp non match",
			pattern:  "/api/v1/user/\\d+",
			endpoint: "/api/v1/user/abc",
			match:    false,
			isErr:    false,
		},
		{
			name:     "mux var match",
			pattern:  "/api/v1/user/{id}",
			endpoint: "/api/v1/user/123",
			match:    true,
			isErr:    false,
		},
		{
			name:     "invalid config regexp",
			pattern:  "/api/v1/[user",
			endpoint: "/api/v1/user",
			match:    false,
			isErr:    true,
		},
		{
			name:     "wildcard endpoint",
			pattern:  "/api/v1/*",
			endpoint: "/api/v1/users",
			match:    true,
			isErr:    false,
		},
		{
			name:     "empty config endpoint",
			pattern:  "",
			endpoint: "/api/v1/user",
			match:    false,
			isErr:    false,
		},
		{
			name:     "empty request endpoint",
			pattern:  "/api/v1/user",
			endpoint: "",
			match:    false,
			isErr:    false,
		},
		{
			name:     "both empty endpoints",
			pattern:  "",
			endpoint: "",
			match:    false,
			isErr:    false,
		},
		{
			name:     "/ endpoint",
			pattern:  "/",
			endpoint: "/",
			match:    true,
			isErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// explicit match inputs as `^/path$`
			pattern := httputil.PreparePathRegexp(tt.pattern, true, true)

			result, err := httputil.MatchPaths(pattern, []string{tt.endpoint})
			assert.Equal(t, tt.match, result)
			assert.Equal(t, tt.isErr, err != nil)
		})
	}
}
