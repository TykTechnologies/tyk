package httputil

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testPathRegexp(tb testing.TB, in string) string {
	tb.Helper()

	res, err := GetPathRegexp(in)
	assert.NoError(tb, err)
	return res
}

func TestGetPathRegexp(t *testing.T) {
	assert.Equal(t, "^/users/(?P<v0>[^/]+)", testPathRegexp(t, "/users/{id}"))
	assert.Equal(t, "^/users/(?P<v0>[^/]+)/profile/(?P<v1>[a-zA-Z]+)", testPathRegexp(t, "/users/{id}/profile/{type:[a-zA-Z]+}"))
	assert.Equal(t, "^/static/(?P<v0>[^/]+)/assets/(?P<v1>[^/]+)", testPathRegexp(t, "/static/{path}/assets/{file}"))
	assert.Equal(t, "^/items/(?P<v0>[0-9]+)/details/(?P<v1>[^/]+)", testPathRegexp(t, "/items/{itemID:[0-9]+}/details/{detail}"))
}

func TestGetPathRegexpWithRegexCompile(t *testing.T) {
	pattern := testPathRegexp(t, "/api/v1/users/{userId}/roles/{roleId}")
	url := "/api/v1/users/10512/roles/32587"

	matched, err := regexp.MatchString(pattern, url)
	assert.NoError(t, err)
	assert.True(t, matched, "The URL should match the pattern")
}
