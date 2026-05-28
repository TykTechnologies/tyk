package httputil_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/cache"
	"github.com/TykTechnologies/tyk/internal/httputil"
)

// TestValidatePath tests mux routes to avoid panics.
// Routes must start with `/` which is an easy check.
func TestValidatePath(t *testing.T) {
	// invalid, paths must start with /
	assert.Error(t, httputil.ValidatePath("{/foo}"))
	assert.Error(t, httputil.ValidatePath("{foo}"))
	assert.Error(t, httputil.ValidatePath("foo"))
	assert.Error(t, httputil.ValidatePath("foo{/foo}"))

	// strange but valid params (basically wildcard?)
	assert.NoError(t, httputil.ValidatePath("/foo/{a!}"))
	assert.NoError(t, httputil.ValidatePath("/foo/{.*}"))
	assert.NoError(t, httputil.ValidatePath("/foo/{*}"))
	assert.NoError(t, httputil.ValidatePath("/foo/{*.}"))

	// invalid regexp in param
	assert.Error(t, httputil.ValidatePath("/foo/{id:*.}"))

	// green path: valid path, param, and param with regexp
	assert.NoError(t, httputil.ValidatePath("/foo"))
	assert.NoError(t, httputil.ValidatePath("/{foo}"))
	assert.NoError(t, httputil.ValidatePath("/{foo:[a-zA-Z0-9]+}"))
}

func pathRegexp(tb testing.TB, in string, want string) string {
	tb.Helper()

	res := httputil.PreparePathRegexp(in, true, false)
	assert.Equal(tb, want, res)
	return res
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
		pathRegexp(t, k, v)
	}
}

func TestGetPathRegexpWithRegexCompile(t *testing.T) {
	pattern := pathRegexp(t, "/api/v1/users/{userId}/roles/{roleId}", "^/api/v1/users/([^/]+)/roles/([^/]+)")

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

// TestPreparePathRegexp_FixedOutputs verifies that PreparePathRegexp produces
// consistent output for a fixed table of (pattern, prefix, suffix) inputs.
func TestPreparePathRegexp_FixedOutputs(t *testing.T) {
	tests := []struct {
		pattern string
		prefix  bool
		suffix  bool
		want    string
	}{
		{"/users", true, false, "^/users"},
		{"/users", true, true, "^/users$"},
		{"/users/{id}", true, false, "^/users/([^/]+)"},
		{"/users/{id}", true, true, "^/users/([^/]+)$"},
		{"users", false, false, "users"},
		{"users", false, true, "users$"},
		{"/items/*", true, false, "^/items/.*"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(fmt.Sprintf("%s prefix=%v suffix=%v", tc.pattern, tc.prefix, tc.suffix), func(t *testing.T) {
			got := httputil.PreparePathRegexp(tc.pattern, tc.prefix, tc.suffix)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestPathRegexpCache_EvictsAtCap verifies eviction at the configured
// cap, with recomputation correctness on a re-fetched key.
func TestPathRegexpCache_EvictsAtCap(t *testing.T) {
	httputil.ConfigurePathRegexpCache(2, false, nil)
	t.Cleanup(func() { httputil.ConfigurePathRegexpCache(0, false, nil) })

	first := "/route-0"
	wantFirst := httputil.PreparePathRegexp(first, true, false)
	httputil.PreparePathRegexp("/route-1", true, false)
	httputil.PreparePathRegexp("/route-2", true, false)

	got := httputil.PreparePathRegexp(first, true, false)
	assert.Equal(t, wantFirst, got, "evicted entry should recompute to same value")
}

// TestConfigurePathRegexpCache covers ConfigurePathRegexpCache behavior across
// maxEntries values:
//   - maxEntries > 0 enforces a cap of exactly that size.
//   - maxEntries <= 0 (without unbounded) clamps to DefaultLRUMaxEntries;
//     it does NOT disable size eviction.
//   - unbounded=true is the only way to disable size eviction.
func TestConfigurePathRegexpCache(t *testing.T) {
	t.Cleanup(func() { httputil.ConfigurePathRegexpCache(0, false, nil) })

	t.Run("bounded", func(t *testing.T) {
		httputil.ConfigurePathRegexpCache(10, false, nil)
		for i := 0; i < 12; i++ {
			httputil.PreparePathRegexp(fmt.Sprintf("/bounded-%d", i), true, false)
		}
		assert.Equal(t, 10, httputil.PathRegexpCacheLen(),
			"cache should cap at maxEntries=10")
	})

	t.Run("negative_clamps_to_default", func(t *testing.T) {
		httputil.ConfigurePathRegexpCache(-1, false, nil)
		for i := 0; i < cache.DefaultLRUMaxEntries+1; i++ {
			httputil.PreparePathRegexp(fmt.Sprintf("/neg-%d", i), true, false)
		}
		assert.Equal(t, cache.DefaultLRUMaxEntries, httputil.PathRegexpCacheLen(),
			"negative maxEntries should clamp to DefaultLRUMaxEntries, not disable eviction")
	})

	t.Run("zero_clamps_to_default", func(t *testing.T) {
		httputil.ConfigurePathRegexpCache(0, false, nil)
		for i := 0; i < cache.DefaultLRUMaxEntries+1; i++ {
			httputil.PreparePathRegexp(fmt.Sprintf("/zero-%d", i), true, false)
		}
		assert.Equal(t, cache.DefaultLRUMaxEntries, httputil.PathRegexpCacheLen(),
			"zero maxEntries should clamp to DefaultLRUMaxEntries")
	})

	t.Run("unbounded", func(t *testing.T) {
		httputil.ConfigurePathRegexpCache(0, true, nil)
		n := cache.DefaultLRUMaxEntries + 100
		for i := 0; i < n; i++ {
			httputil.PreparePathRegexp(fmt.Sprintf("/unb-%d", i), true, false)
		}
		assert.Equal(t, n, httputil.PathRegexpCacheLen(),
			"unbounded should allow growth past DefaultLRUMaxEntries")
	})

	t.Run("unbounded_no_eviction_log", func(t *testing.T) {
		var logged []string
		logFunc := func(format string, args ...any) {
			logged = append(logged, fmt.Sprintf(format, args...))
		}
		// Wire a real logger but unbounded=true: reporter must not be created.
		httputil.ConfigurePathRegexpCache(0, true, logFunc)
		// Add more entries than the default cap to guarantee size eviction would
		// fire if the reporter were wired.
		for i := 0; i < cache.DefaultLRUMaxEntries+100; i++ {
			httputil.PreparePathRegexp(fmt.Sprintf("/unb-log-%d", i), true, false)
		}
		assert.Empty(t, logged, "unbounded cache must not produce eviction log lines")
	})
}
