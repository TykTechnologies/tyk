package httputil

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRouteRegexString(t *testing.T) {
	assert.Equal(t, "^/users/.*$", RouteRegexString("/users/{id}"))
	assert.Equal(t, "^/users/.*/profile/[a-zA-Z]+$", RouteRegexString("/users/{id}/profile/{type:[a-zA-Z]+}"))
	assert.Equal(t, "^/static/.*/assets/.*$", RouteRegexString("/static/{path}/assets/{file}"))
	assert.Equal(t, "^/items/[0-9]+/details/.*$", RouteRegexString("/items/{itemID:[0-9]+}/details/{detail}"))
}

func TestRouteRegexStringWithRegexCompile(t *testing.T) {
	pattern := RouteRegexString("/api/v1/users/{userId}/roles/{roleId}")
	url := "/api/v1/users/10512/roles/32587"

	matched, err := regexp.MatchString(pattern, url)
	assert.NoError(t, err)
	assert.True(t, matched, "The URL should match the pattern")
}
