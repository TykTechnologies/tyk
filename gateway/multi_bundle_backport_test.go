package gateway

import (
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// TestParseBundleNames covers the comma-splitting/trimming contract that the
// multi-bundle dispatcher relies on: a bare filename yields a single element
// equal to the input, whitespace is trimmed, empty entries are dropped, and an
// empty/comma-only input yields nothing.
func TestParseBundleNames(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single", "bundle.zip", []string{"bundle.zip"}},
		{"single with surrounding space", "  bundle.zip  ", []string{"bundle.zip"}},
		{"two", "a.zip,b.zip", []string{"a.zip", "b.zip"}},
		{"two with spaces", " a.zip , b.zip ", []string{"a.zip", "b.zip"}},
		{"trailing comma", "a.zip,", []string{"a.zip"}},
		{"empty middle entry", "a.zip,,b.zip", []string{"a.zip", "b.zip"}},
		{"only commas and spaces", ", , ", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseBundleNames(tc.in))
		})
	}

	// The single-bundle fast path in loadBundleWithFs keys off the parsed
	// result being exactly one element equal to the untrimmed input. Lock in
	// that a bare name (no comma, no padding) satisfies it.
	got := parseBundleNames("bundle.zip")
	require.Len(t, got, 1)
	assert.Equal(t, "bundle.zip", got[0])
}

// TestMergeBundleManifestAppendsHooks verifies the multi-bundle merge
// concatenates every array hook (pre/post/post_key_auth/response) in
// declaration order across bundles and within each bundle, and that each
// entry's Path is prefixed with the bundle's subdir so api_loader's
// prefix-join resolves to the correct file. Driver-agnostic (uses grpc).
func TestMergeBundleManifestAppendsHooks(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}

	a := &apidef.BundleManifest{
		CustomMiddleware: apidef.MiddlewareSection{
			Driver: apidef.GrpcDriver,
			Pre: []apidef.MiddlewareDefinition{
				{Name: "preA1", Path: "plugin.so"},
				{Name: "preA2", Path: "plugin.so"},
			},
			Post: []apidef.MiddlewareDefinition{
				{Name: "postA1", Path: "plugin.so"},
			},
			PostKeyAuth: []apidef.MiddlewareDefinition{
				{Name: "pkaA1", Path: "plugin.so"},
			},
		},
	}
	b := &apidef.BundleManifest{
		CustomMiddleware: apidef.MiddlewareSection{
			Driver: apidef.GrpcDriver,
			Pre: []apidef.MiddlewareDefinition{
				{Name: "preB1", Path: "plugin.so"},
			},
			PostKeyAuth: []apidef.MiddlewareDefinition{
				{Name: "pkaB1", Path: "plugin.so"},
				{Name: "pkaB2", Path: "plugin.so"},
			},
			Response: []apidef.MiddlewareDefinition{
				{Name: "respB1", Path: "plugin.so"},
			},
		},
	}

	require.NoError(t, mergeBundleManifest(spec, a, "bundle-a", "bundle-a.zip"))
	require.NoError(t, mergeBundleManifest(spec, b, "bundle-b", "bundle-b.zip"))

	// pre: A's two then B's one, all path-prefixed by their bundle subdir.
	require.Len(t, spec.CustomMiddleware.Pre, 3)
	assert.Equal(t, []string{"preA1", "preA2", "preB1"}, []string{
		spec.CustomMiddleware.Pre[0].Name,
		spec.CustomMiddleware.Pre[1].Name,
		spec.CustomMiddleware.Pre[2].Name,
	})
	assert.True(t, strings.HasPrefix(spec.CustomMiddleware.Pre[0].Path, "bundle-a"))
	assert.True(t, strings.HasPrefix(spec.CustomMiddleware.Pre[1].Path, "bundle-a"))
	assert.True(t, strings.HasPrefix(spec.CustomMiddleware.Pre[2].Path, "bundle-b"))

	// post_key_auth: A's one then B's two.
	require.Len(t, spec.CustomMiddleware.PostKeyAuth, 3)
	assert.Equal(t, []string{"pkaA1", "pkaB1", "pkaB2"}, []string{
		spec.CustomMiddleware.PostKeyAuth[0].Name,
		spec.CustomMiddleware.PostKeyAuth[1].Name,
		spec.CustomMiddleware.PostKeyAuth[2].Name,
	})
	assert.True(t, strings.HasPrefix(spec.CustomMiddleware.PostKeyAuth[0].Path, "bundle-a"))
	assert.True(t, strings.HasPrefix(spec.CustomMiddleware.PostKeyAuth[2].Path, "bundle-b"))

	// post: only from A.
	require.Len(t, spec.CustomMiddleware.Post, 1)
	assert.True(t, strings.HasPrefix(spec.CustomMiddleware.Post[0].Path, "bundle-a"))

	// response: only from B.
	require.Len(t, spec.CustomMiddleware.Response, 1)
	assert.True(t, strings.HasPrefix(spec.CustomMiddleware.Response[0].Path, "bundle-b"))

	// driver propagated and consistent across both bundles.
	assert.Equal(t, apidef.GrpcDriver, spec.CustomMiddleware.Driver)
}

// TestMergeBundleManifestEmptyPathNotPrefixed verifies a middleware entry with
// no Path (nothing to mount on disk) is not given a spurious subdir prefix.
func TestMergeBundleManifestEmptyPathNotPrefixed(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}

	manifest := &apidef.BundleManifest{
		CustomMiddleware: apidef.MiddlewareSection{
			Driver: apidef.GrpcDriver,
			Pre: []apidef.MiddlewareDefinition{
				{Name: "noPath"},                    // empty Path stays empty
				{Name: "withPath", Path: "hook.so"}, // gets prefixed
			},
		},
	}

	require.NoError(t, mergeBundleManifest(spec, manifest, "bundle-a", "bundle-a.zip"))
	require.Len(t, spec.CustomMiddleware.Pre, 2)
	assert.Empty(t, spec.CustomMiddleware.Pre[0].Path, "empty Path must not get a subdir prefix")
	assert.True(t, strings.HasPrefix(spec.CustomMiddleware.Pre[1].Path, "bundle-a"))
}

// TestMergeBundleManifestRejectsDuplicateAuthCheck enforces that only one
// bundle may declare an auth_check hook per API.
func TestMergeBundleManifestRejectsDuplicateAuthCheck(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}

	a := &apidef.BundleManifest{
		CustomMiddleware: apidef.MiddlewareSection{
			Driver:    apidef.GrpcDriver,
			AuthCheck: apidef.MiddlewareDefinition{Name: "authA", Path: "plugin.so"},
		},
	}
	b := &apidef.BundleManifest{
		CustomMiddleware: apidef.MiddlewareSection{
			Driver:    apidef.GrpcDriver,
			AuthCheck: apidef.MiddlewareDefinition{Name: "authB", Path: "plugin.so"},
		},
	}

	require.NoError(t, mergeBundleManifest(spec, a, "bundle-a", "bundle-a.zip"))
	err := mergeBundleManifest(spec, b, "bundle-b", "bundle-b.zip")
	require.Error(t, err, "second auth_check must be rejected")
	assert.Contains(t, err.Error(), "auth_check")

	// The first bundle's auth_check must remain intact after rejection.
	assert.Equal(t, "authA", spec.CustomMiddleware.AuthCheck.Name)
}

// TestMergeBundleManifestRejectsDriverMismatch enforces driver uniformity
// across composed bundles.
func TestMergeBundleManifestRejectsDriverMismatch(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}

	a := &apidef.BundleManifest{
		CustomMiddleware: apidef.MiddlewareSection{Driver: apidef.GrpcDriver},
	}
	b := &apidef.BundleManifest{
		CustomMiddleware: apidef.MiddlewareSection{Driver: apidef.GoPluginDriver},
	}

	require.NoError(t, mergeBundleManifest(spec, a, "bundle-a", "bundle-a.zip"))
	err := mergeBundleManifest(spec, b, "bundle-b", "bundle-b.zip")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "driver")
}

// TestBundleSubdirNameStripsExtAndCollapsesSlashes verifies the per-bundle
// directory name derivation is filesystem-safe and stable.
func TestBundleSubdirNameStripsExtAndCollapsesSlashes(t *testing.T) {
	assert.Equal(t, "correlation-id-1.4.0", bundleSubdirName("correlation-id-1.4.0.zip"))
	assert.Equal(t, "platform__correlation-id-1.4.0", bundleSubdirName("platform/correlation-id-1.4.0.zip"))
	assert.Equal(t, "a__b", bundleSubdirName("a\\b.zip"))
	assert.NotEmpty(t, bundleSubdirName("")) // fallback hash path
}

// TestLoadBundleWithFs_EarlyReturns covers the short-circuit branches at the
// top of loadBundleWithFs: management node, bundle explicitly disabled, empty
// CustomMiddlewareBundle, and a comma/space-only value that parses to nothing.
// All must return nil without touching the filesystem.
//
// Uses StartTest, so requires a running Redis.
func TestLoadBundleWithFs_EarlyReturns(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("management node skips bundle loading", func(t *testing.T) {
		conf := ts.Gw.GetConfig()
		conf.ManagementNode = true
		ts.Gw.SetConfig(conf)
		defer func() {
			conf.ManagementNode = false
			ts.Gw.SetConfig(conf)
		}()

		spec := &APISpec{APIDefinition: &apidef.APIDefinition{CustomMiddlewareBundle: "anything.zip"}}
		assert.NoError(t, ts.Gw.loadBundleWithFs(spec, afero.NewMemMapFs()))
	})

	t.Run("disabled flag skips bundle loading", func(t *testing.T) {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{
			CustomMiddlewareBundle:         "anything.zip",
			CustomMiddlewareBundleDisabled: true,
		}}
		assert.NoError(t, ts.Gw.loadBundleWithFs(spec, afero.NewMemMapFs()))
	})

	t.Run("empty bundle field is a no-op", func(t *testing.T) {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{CustomMiddlewareBundle: ""}}
		assert.NoError(t, ts.Gw.loadBundleWithFs(spec, afero.NewMemMapFs()))
	})

	t.Run("bundle field with only commas parses to nothing", func(t *testing.T) {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{CustomMiddlewareBundle: ", , "}}
		assert.NoError(t, ts.Gw.loadBundleWithFs(spec, afero.NewMemMapFs()))
	})
}

// mergeBundleManifestJSON builds a minimal, checksum-valid bundle manifest.
// file_list is empty, so the md5 checksum over the (zero) referenced files is
// the well-known md5 of the empty input; DeepVerify therefore passes without
// any signature configured.
func mergeBundleManifestJSON(driver, middlewareBody string) map[string]string {
	return map[string]string{
		"manifest.json": `{
			"file_list": [],
			"custom_middleware": {
				"driver": "` + driver + `",
				` + middlewareBody + `
			},
			"checksum": "d41d8cd98f00b204e9800998ecf8427e"
		}`,
	}
}

// testMultiBundleMerge is the shared body for the driver-parameterised
// integration test. It registers two bundles over the test HTTP bundle server,
// loads them via a comma-separated CustomMiddlewareBundle, and asserts both
// bundles' hooks land in the merged spec in order with subdir-prefixed paths.
//
// This exercises the real fetch → unzip → verify → merge pipeline end to end
// (no external gRPC/goplugin server is needed, because the merge operates on
// manifests). Requires a running Redis via StartTest.
func testMultiBundleMerge(t *testing.T, driver string) {
	t.Helper()

	ts := StartTest(nil)
	defer ts.Close()

	bundleA := ts.RegisterBundle("multi_merge_a", mergeBundleManifestJSON(driver,
		`"pre": [{"name": "PreHookA", "path": "plugin.so"}]`))
	bundleB := ts.RegisterBundle("multi_merge_b", mergeBundleManifestJSON(driver,
		`"post": [{"name": "PostHookB", "path": "plugin.so"}],
		 "auth_check": {"name": "AuthHookB", "path": "plugin.so"}`))

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:                  "multi-bundle-" + driver,
			CustomMiddlewareBundle: bundleA + "," + bundleB,
		},
	}

	require.NoError(t, ts.Gw.loadBundle(spec))

	// Driver propagated uniformly.
	assert.Equal(t, apidef.MiddlewareDriver(driver), spec.CustomMiddleware.Driver)

	// Bundle A's pre hook and bundle B's post/auth hooks all present.
	require.Len(t, spec.CustomMiddleware.Pre, 1)
	assert.Equal(t, "PreHookA", spec.CustomMiddleware.Pre[0].Name)
	require.Len(t, spec.CustomMiddleware.Post, 1)
	assert.Equal(t, "PostHookB", spec.CustomMiddleware.Post[0].Name)
	assert.Equal(t, "AuthHookB", spec.CustomMiddleware.AuthCheck.Name)

	// Each entry's Path is prefixed with its own bundle's subdir, so the two
	// bundles' files resolve independently on disk.
	preSubdir := bundleSubdirName(bundleA)
	postSubdir := bundleSubdirName(bundleB)
	assert.True(t, strings.HasPrefix(spec.CustomMiddleware.Pre[0].Path, preSubdir),
		"pre hook path %q must be prefixed with %q", spec.CustomMiddleware.Pre[0].Path, preSubdir)
	assert.True(t, strings.HasPrefix(spec.CustomMiddleware.Post[0].Path, postSubdir),
		"post hook path %q must be prefixed with %q", spec.CustomMiddleware.Post[0].Path, postSubdir)
	assert.NotEqual(t, preSubdir, postSubdir, "bundles must unpack into distinct subdirs")
}

// TestMultiBundleMerge_GRPC loads two grpc-driver bundles and asserts their
// hooks merge in order. Requires a running Redis.
func TestMultiBundleMerge_GRPC(t *testing.T) {
	testMultiBundleMerge(t, "grpc")
}

// TestMultiBundleMerge_GoPlugin loads two goplugin-driver bundles and asserts
// their hooks merge in order. The goplugin driver is not a registered
// dispatcher, so the post-merge HandleMiddlewareCache finalizer is a harmless
// no-op — the manifest-level merge is identical to grpc. Requires a running
// Redis.
func TestMultiBundleMerge_GoPlugin(t *testing.T) {
	testMultiBundleMerge(t, "goplugin")
}
