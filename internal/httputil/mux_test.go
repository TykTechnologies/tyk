package httputil_test

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/httputil"
)

func testPathRegexp(tb testing.TB, in string, want string) string {
	tb.Helper()

	res, err := httputil.GetPathRegexp(in)
	assert.NoError(tb, err)
	if want != "" {
		assert.Equal(tb, want, res)
	}
	return res
}

func TestGetPathRegexp(t *testing.T) {
	tests := map[string]string{
		"/users*.":                             "^/users*.",
		"/users":                               "^/users",
		"users":                                "^.*users",
		"/users$":                              "^/users$",
		"/users/.*":                            "^/users/.*",
		"/users/{id}":                          "^/users/(?P<v0>[^/]+)",
		"/users/{id}/profile/{type:[a-zA-Z]+}": "^/users/(?P<v0>[^/]+)/profile/(?P<v1>[a-zA-Z]+)",
		"/static/{path}/assets/{file}":         "^/static/(?P<v0>[^/]+)/assets/(?P<v1>[^/]+)",
		"/items/{itemID:[0-9]+}/details/{detail}": "^/items/(?P<v0>[0-9]+)/details/(?P<v1>[^/]+)",
	}

	for k, v := range tests {
		testPathRegexp(t, k, v)
	}
}

func TestGetPathRegexpWithRegexCompile(t *testing.T) {
	pattern := testPathRegexp(t, "/api/v1/users/{userId}/roles/{roleId}", "")

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

func TestMatchEndpoint(t *testing.T) {
	tests := []struct {
		name           string
		configEndpoint string
		reqEndpoint    string
		match          bool
		isErr          bool
	}{
		{
			name:           "exact endpoints",
			configEndpoint: "/api/v1/users",
			reqEndpoint:    "/api/v1/users",
			match:          true,
			isErr:          false,
		},
		{
			name:           "non matching concrete endpoints",
			configEndpoint: "/api/v1/users",
			reqEndpoint:    "/api/v1/admin",
			match:          false,
			isErr:          false,
		},
		{
			name:           "regexp match",
			configEndpoint: "/api/v1/user/\\d+",
			reqEndpoint:    "/api/v1/user/123",
			match:          true,
			isErr:          false,
		},
		{
			name:           "invalid config regexp",
			configEndpoint: "/api/v1/[user",
			reqEndpoint:    "/api/v1/user",
			match:          false,
			isErr:          true,
		},
		{
			name:           "wildcard endpoint",
			configEndpoint: "/api/v1/*",
			reqEndpoint:    "/api/v1/users",
			match:          true,
			isErr:          false,
		},
		{
			name:           "empty config endpoint",
			configEndpoint: "",
			reqEndpoint:    "/api/v1/user",
			match:          false,
			isErr:          false,
		},
		{
			name:           "empty request endpoint",
			configEndpoint: "/api/v1/user",
			reqEndpoint:    "",
			match:          false,
			isErr:          false,
		},
		{
			name:           "both empty endpoints",
			configEndpoint: "",
			reqEndpoint:    "",
			match:          true,
			isErr:          false,
		},
		{
			name:           "/ endpoint",
			configEndpoint: "/",
			reqEndpoint:    "/",
			match:          true,
			isErr:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := httputil.MatchEndpoint(tt.configEndpoint, tt.reqEndpoint)
			assert.Equal(t, tt.match, result)
			if tt.isErr {
				assert.Error(t, err)
			}
		})
	}
}
