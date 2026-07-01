package httputil_test

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/httputil"
)

// Verifies: STK-REQ-084, SYS-REQ-172, SW-REQ-159
// MCDC SYS-REQ-172: http_mux_path_helpers_operation_terminal=T => TRUE
// MCDC SW-REQ-159: http_mux_path_helpers_operation_terminal=T => TRUE
// STK-REQ-084:STK-REQ-084-AC-01:acceptance
// STK-REQ-084:error_handling:negative
// SW-REQ-159:nominal:nominal
// SW-REQ-159:boundary:nominal
// SW-REQ-159:error_handling:nominal
// SW-REQ-159:error_handling:negative
// SW-REQ-159:determinism:nominal
func TestHTTPMuxPathHelpersReqProof(t *testing.T) {
	t.Run("validate mux path patterns", func(t *testing.T) {
		tests := []struct {
			name    string
			path    string
			wantErr bool
		}{
			{name: "valid literal path", path: "/foo"},
			{name: "valid parameter regexp", path: "/{foo:[a-zA-Z0-9]+}"},
			{name: "missing leading slash", path: "foo", wantErr: true},
			{name: "invalid parameter regexp", path: "/foo/{id:*.}", wantErr: true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := httputil.ValidatePath(tt.path)
				assert.Equal(t, tt.wantErr, err != nil)
			})
		}
	})

	t.Run("prepare path regexp", func(t *testing.T) {
		tests := []struct {
			name    string
			pattern string
			prefix  bool
			suffix  bool
			want    string
		}{
			{name: "literal path prefix", pattern: "/users", prefix: true, want: "^/users"},
			{name: "mux id with suffix", pattern: "/users/{id}", prefix: true, suffix: true, want: "^/users/([^/]+)$"},
			{name: "wildcard suffix", pattern: "/files/*", prefix: true, suffix: true, want: "^/files/.*$"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := httputil.PreparePathRegexp(tt.pattern, tt.prefix, tt.suffix)
				assert.Equal(t, tt.want, got)

				if tt.name == "mux id with suffix" {
					assert.True(t, regexp.MustCompile(got).MatchString("/users/123"))
				}
			})
		}
	})

	t.Run("identify mux templates", func(t *testing.T) {
		tests := []struct {
			name    string
			pattern string
			want    bool
		}{
			{name: "template", pattern: "/users/{id}", want: true},
			{name: "plain literal", pattern: "/users/id"},
			{name: "unbalanced template", pattern: "/users/{id"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.want, httputil.IsMuxTemplate(tt.pattern))
			})
		}
	})

	t.Run("strip listen paths", func(t *testing.T) {
		tests := []struct {
			name       string
			listenPath string
			urlPath    string
			want       string
		}{
			{name: "literal listen path", listenPath: "/listen", urlPath: "/listen/get", want: "/get"},
			{name: "mux wildcard path", listenPath: "/{_:.*}/post/", urlPath: "/listen/post/get", want: "/get"},
			{name: "non-matching mux path", listenPath: "/{myPattern:foo|bar}", urlPath: "/anything/get", want: "/anything/get"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.want, httputil.StripListenPath(tt.listenPath, tt.urlPath))
			})
		}
	})

	t.Run("match single path patterns", func(t *testing.T) {
		tests := []struct {
			name     string
			pattern  string
			endpoint string
			want     bool
			wantErr  bool
		}{
			{name: "exact match", pattern: "/api/v1/users", endpoint: "/api/v1/users", want: true},
			{name: "regexp match", pattern: "^/api/v1/user/\\d+$", endpoint: "/api/v1/user/123", want: true},
			{name: "regexp non-match", pattern: "^/api/v1/user/\\d+$", endpoint: "/api/v1/user/abc"},
			{name: "invalid regexp", pattern: "/api/v1/[user", endpoint: "/api/v1/user", wantErr: true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := httputil.MatchPath(tt.pattern, tt.endpoint)
				assert.Equal(t, tt.wantErr, err != nil)
				assert.Equal(t, tt.want, got)
			})
		}
	})

	t.Run("match any candidate path", func(t *testing.T) {
		tests := []struct {
			name      string
			pattern   string
			endpoints []string
			want      bool
			wantErr   bool
		}{
			{name: "later candidate matches", pattern: "^/api/v1/user/\\d+$", endpoints: []string{"/api/v1/user/abc", "/api/v1/user/123"}, want: true},
			{name: "no candidate matches", pattern: "^/api/v1/user/\\d+$", endpoints: []string{"/api/v1/user/abc"}},
			{name: "malformed regexp returns error", pattern: "/api/v1/[user", endpoints: []string{"/api/v1/user"}, wantErr: true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := httputil.MatchPaths(tt.pattern, tt.endpoints)
				assert.Equal(t, tt.wantErr, err != nil)
				assert.Equal(t, tt.want, got)
			})
		}
	})
}
