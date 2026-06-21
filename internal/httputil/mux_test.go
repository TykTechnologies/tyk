package httputil_test

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/httputil"
)

// TestValidatePath tests mux routes to avoid panics. Routes must start with `/`.
// Verifies: STK-REQ-084, SYS-REQ-172, SW-REQ-159
// STK-REQ-084:STK-REQ-084-AC-01:acceptance
// STK-REQ-084:error_handling:negative
// SW-REQ-159:nominal:nominal
// SW-REQ-159:boundary:nominal
// SW-REQ-159:error_handling:nominal
// SW-REQ-159:error_handling:negative
// SW-REQ-159:determinism:nominal
func TestValidatePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{name: "missing leading slash with slash in variable", path: "{/foo}", wantErr: true},
		{name: "missing leading slash variable", path: "{foo}", wantErr: true},
		{name: "missing leading slash literal", path: "foo", wantErr: true},
		{name: "missing leading slash with later variable", path: "foo{/foo}", wantErr: true},
		{name: "invalid regexp in param", path: "/foo/{id:*.}", wantErr: true},
		{name: "valid unusual param bang", path: "/foo/{a!}"},
		{name: "valid unusual param dot star", path: "/foo/{.*}"},
		{name: "valid unusual param star", path: "/foo/{*}"},
		{name: "valid unusual param star dot", path: "/foo/{*.}"},
		{name: "valid literal path", path: "/foo"},
		{name: "valid param", path: "/{foo}"},
		{name: "valid param regexp", path: "/{foo:[a-zA-Z0-9]+}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := httputil.ValidatePath(tt.path)
			assert.Equal(t, tt.wantErr, err != nil)
		})
	}
}

func pathRegexp(tb testing.TB, in string, want string) string {
	tb.Helper()

	res := httputil.PreparePathRegexp(in, true, false)
	assert.Equal(tb, want, res)
	return res
}

// Verifies: STK-REQ-084, SYS-REQ-172, SW-REQ-159
// SW-REQ-159:nominal:nominal
// SW-REQ-159:boundary:nominal
// SW-REQ-159:determinism:nominal
func TestPreparePathRegexp(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		prefix  bool
		suffix  bool
		want    string
	}{
		{name: "literal special character", pattern: "/users*.", prefix: true, want: "^/users*."},
		{name: "literal path prefix", pattern: "/users", prefix: true, want: "^/users"},
		{name: "relative path no prefix", pattern: "users", prefix: true, want: "users"},
		{name: "already anchored", pattern: "^/test/users", prefix: true, want: "^/test/users"},
		{name: "already suffixed", pattern: "/users$", prefix: true, suffix: true, want: "^/users$"},
		{name: "wildcard regexp preserved", pattern: "/users/.*", prefix: true, want: "^/users/.*"},
		{name: "mux id", pattern: "/users/{id}", prefix: true, want: "^/users/([^/]+)"},
		{name: "mux id with suffix", pattern: "/users/{id}", prefix: true, suffix: true, want: "^/users/([^/]+)$"},
		{name: "mux id already suffixed", pattern: "/users/{id}$", prefix: true, want: "^/users/([^/]+)$"},
		{name: "multiple mux params", pattern: "/users/{id}/profile/{type:[a-zA-Z]+}", prefix: true, want: "^/users/([^/]+)/profile/([^/]+)"},
		{name: "multiple simple mux params", pattern: "/static/{path}/assets/{file}", prefix: true, want: "^/static/([^/]+)/assets/([^/]+)"},
		{name: "mux param with regexp and simple param", pattern: "/items/{itemID:[0-9]+}/details/{detail}", prefix: true, want: "^/items/([^/]+)/details/([^/]+)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, httputil.PreparePathRegexp(tt.pattern, tt.prefix, tt.suffix))
		})
	}
}

// Verifies: STK-REQ-084, SYS-REQ-172, SW-REQ-159
// SW-REQ-159:nominal:nominal
// SW-REQ-159:boundary:nominal
// SW-REQ-159:determinism:nominal
func TestIsMuxTemplate(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    bool
	}{
		{name: "simple template", pattern: "/users/{id}", want: true},
		{name: "regexp template", pattern: "/users/{id:[0-9]+}", want: true},
		{name: "no braces", pattern: "/users/id"},
		{name: "unbalanced open brace", pattern: "/users/{id"},
		{name: "unbalanced close brace", pattern: "/users/id}"},
		{name: "empty string", pattern: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, httputil.IsMuxTemplate(tt.pattern))
		})
	}
}

// Verifies: STK-REQ-084, SYS-REQ-172, SW-REQ-159
// SW-REQ-159:nominal:nominal
// SW-REQ-159:boundary:nominal
// SW-REQ-159:determinism:nominal
func TestGetPathRegexpWithRegexCompile(t *testing.T) {
	pattern := pathRegexp(t, "/api/v1/users/{userId}/roles/{roleId}", "^/api/v1/users/([^/]+)/roles/([^/]+)")

	matched, err := regexp.MatchString(pattern, "/api/v1/users/10512/roles/32587")
	assert.NoError(t, err)
	assert.True(t, matched, "The URL should match the pattern")
}

// Verifies: STK-REQ-084, SYS-REQ-172, SW-REQ-159
// SW-REQ-159:nominal:nominal
// SW-REQ-159:boundary:nominal
// SW-REQ-159:determinism:nominal
func TestStripListenPath(t *testing.T) {
	tests := []struct {
		name       string
		listenPath string
		urlPath    string
		want       string
	}{
		{name: "slash listen path", listenPath: "/listen", urlPath: "/listen/get", want: "/get"},
		{name: "slash listen path with trailing slash", listenPath: "/listen/", urlPath: "/listen/get", want: "/get"},
		{name: "relative listen path", listenPath: "listen", urlPath: "listen/get", want: "/get"},
		{name: "relative listen path with trailing slash", listenPath: "listen/", urlPath: "listen/get", want: "/get"},
		{name: "slash listen path root remainder", listenPath: "/listen/", urlPath: "/listen/", want: "/"},
		{name: "slash listen path exact", listenPath: "/listen", urlPath: "/listen", want: "/"},
		{name: "relative listen path empty request path", listenPath: "listen/", urlPath: "", want: "/"},
		{name: "mux wildcard middle path", listenPath: "/{_:.*}/post/", urlPath: "/listen/post/get", want: "/get"},
		{name: "mux wildcard prefix", listenPath: "/{_:.*}/", urlPath: "/listen/get", want: "/get"},
		{name: "mux wildcard after prefix", listenPath: "/pre/{_:.*}/", urlPath: "/pre/listen/get", want: "/get"},
		{name: "mux wildcard exact", listenPath: "/{_:.*}", urlPath: "/listen", want: "/"},
		{name: "mux alternation match", listenPath: "/{myPattern:foo|bar}", urlPath: "/foo/get", want: "/get"},
		{name: "mux alternation non-match", listenPath: "/{myPattern:foo|bar}", urlPath: "/anything/get", want: "/anything/get"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, httputil.StripListenPath(tt.listenPath, tt.urlPath))
		})
	}
}

// Verifies: STK-REQ-084, SYS-REQ-172, SW-REQ-159
// SW-REQ-159:nominal:nominal
// SW-REQ-159:boundary:nominal
// SW-REQ-159:error_handling:nominal
// SW-REQ-159:error_handling:negative
// SW-REQ-159:determinism:nominal
func TestMatchPath(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		endpoint string
		want     bool
		wantErr  bool
	}{
		{name: "exact match", pattern: "/api/v1/users", endpoint: "/api/v1/users", want: true},
		{name: "anchored exact match", pattern: "^/api/v1/users$", endpoint: "/api/v1/users", want: true},
		{name: "regexp match", pattern: "^/api/v1/user/\\d+$", endpoint: "/api/v1/user/123", want: true},
		{name: "regexp non-match", pattern: "^/api/v1/user/\\d+$", endpoint: "/api/v1/user/abc"},
		{name: "empty pattern", pattern: "", endpoint: "/api/v1/user"},
		{name: "empty endpoint", pattern: "/api/v1/user", endpoint: ""},
		{name: "invalid regexp", pattern: "/api/v1/[user", endpoint: "/api/v1/user", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := httputil.MatchPath(tt.pattern, tt.endpoint)
			assert.Equal(t, tt.wantErr, err != nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

// Verifies: STK-REQ-084, SYS-REQ-172, SW-REQ-159
// SW-REQ-159:nominal:nominal
// SW-REQ-159:boundary:nominal
// SW-REQ-159:error_handling:nominal
// SW-REQ-159:error_handling:negative
// SW-REQ-159:determinism:nominal
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
			name:     "invalid config regexp only candidate",
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

	t.Run("match after earlier invalid regexp ignores joined error", func(t *testing.T) {
		match, err := httputil.MatchPaths("/api/v1/[user", []string{"/api/v1/user"})
		assert.False(t, match)
		assert.Error(t, err)

		match, err = httputil.MatchPaths("/api/v1/user/\\d+", []string{"/api/v1/user/abc", "/api/v1/user/123"})
		assert.True(t, match)
		assert.NoError(t, err)
	})
}
