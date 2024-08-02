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
