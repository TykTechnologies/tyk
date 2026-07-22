package gateway

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

func enableLabsMultiBundle(c *config.Config) {
	c.EnableLabsMultiBundle = true
}

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
	ts := StartTest(enableLabsMultiBundle)
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

	ts := StartTest(enableLabsMultiBundle)
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

// stagePreUnpackedBundle writes a manifest.json into the per-bundle subdir on
// the supplied FS so loadOneBundleForMerge takes the "existing bundle on disk"
// branch (Stat succeeds → loadBundleManifestNamed with partial=true) instead of
// fetching over HTTP. The checksum/signature are dummies because callers set
// SkipVerifyExistingPluginBundle=true, so PartialVerify short-circuits.
func stagePreUnpackedBundle(t *testing.T, fs afero.Fs, rootPath, bundleName, manifestJSON string) {
	t.Helper()
	subdir := bundleSubdirName(bundleName)
	dir := filepath.Join(rootPath, subdir)
	require.NoError(t, fs.MkdirAll(dir, 0755))
	f, err := fs.Create(filepath.Join(dir, "manifest.json"))
	require.NoError(t, err)
	_, err = f.WriteString(manifestJSON)
	require.NoError(t, err)
	require.NoError(t, f.Close())
}

// TestLoadBundleWithFs_OnDiskReuseMergesBothBundles is master's dropped
// TestLoadBundleWithFs_CommaSeparatedMergesBothBundles (driver swapped
// javascript→grpc). Both bundles are pre-staged on the in-memory FS, so
// loadOneBundleForMerge takes the existing-bundle branch (Stat ok →
// loadBundleManifestNamed partial=true, lines 636-643 + 707-709) and NO HTTP
// fetch happens. SkipVerifyExistingPluginBundle=true skips signature checks.
// Requires a running Redis.
func TestLoadBundleWithFs_OnDiskReuseMergesBothBundles(t *testing.T) {
	ts := StartTest(func(c *config.Config) {
		enableLabsMultiBundle(c)
		c.BundleBaseURL = "http://bundles.local/"
		c.SkipVerifyExistingPluginBundle = true
	})
	defer ts.Close()

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:                  "multi-bundle-ondisk",
			CustomMiddlewareBundle: "bundle-a.zip,bundle-b.zip",
		},
	}

	rootPath := ts.Gw.getBundleDestPath(spec)
	subdirA := bundleSubdirName("bundle-a.zip")
	subdirB := bundleSubdirName("bundle-b.zip")

	memFs := afero.NewMemMapFs()
	stagePreUnpackedBundle(t, memFs, rootPath, "bundle-a.zip", `{
		"file_list": ["plugin.so"],
		"custom_middleware": {
			"driver": "grpc",
			"pre":  [{"name": "preA",  "path": "plugin.so"}],
			"post": [{"name": "postA", "path": "plugin.so"}]
		},
		"checksum": "deadbeef",
		"signature": ""
	}`)
	stagePreUnpackedBundle(t, memFs, rootPath, "bundle-b.zip", `{
		"file_list": ["plugin.so"],
		"custom_middleware": {
			"driver": "grpc",
			"pre":      [{"name": "preB",      "path": "plugin.so"}],
			"response": [{"name": "responseB", "path": "plugin.so"}]
		},
		"checksum": "deadbeef",
		"signature": ""
	}`)

	require.NoError(t, ts.Gw.loadBundleWithFs(spec, memFs))

	require.Len(t, spec.CustomMiddleware.Pre, 2)
	assert.Equal(t, "preA", spec.CustomMiddleware.Pre[0].Name)
	assert.True(t, strings.HasPrefix(spec.CustomMiddleware.Pre[0].Path, subdirA))
	assert.Equal(t, "preB", spec.CustomMiddleware.Pre[1].Name)
	assert.True(t, strings.HasPrefix(spec.CustomMiddleware.Pre[1].Path, subdirB))

	require.Len(t, spec.CustomMiddleware.Post, 1)
	assert.Equal(t, "postA", spec.CustomMiddleware.Post[0].Name)
	assert.True(t, strings.HasPrefix(spec.CustomMiddleware.Post[0].Path, subdirA))

	require.Len(t, spec.CustomMiddleware.Response, 1)
	assert.Equal(t, "responseB", spec.CustomMiddleware.Response[0].Name)
	assert.True(t, strings.HasPrefix(spec.CustomMiddleware.Response[0].Path, subdirB))

	assert.Equal(t, apidef.GrpcDriver, spec.CustomMiddleware.Driver)
}

// TestLoadBundleWithFs_ResetsStaleCustomMiddleware pins the line-518 behaviour:
// multi-bundle mode is the source of truth for hooks, so any middleware already
// attached to the spec is discarded before merging. We pre-populate a stale Pre
// hook, run a 2-bundle on-disk merge, and assert the stale entry is gone and
// only the merged hooks remain. Requires a running Redis.
func TestLoadBundleWithFs_ResetsStaleCustomMiddleware(t *testing.T) {
	ts := StartTest(func(c *config.Config) {
		enableLabsMultiBundle(c)
		c.BundleBaseURL = "http://bundles.local/"
		c.SkipVerifyExistingPluginBundle = true
	})
	defer ts.Close()

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:                  "multi-bundle-reset",
			CustomMiddlewareBundle: "bundle-a.zip,bundle-b.zip",
		},
	}
	// Stale middleware that must be wiped by the reset at line 518.
	spec.CustomMiddleware = apidef.MiddlewareSection{
		Pre: []apidef.MiddlewareDefinition{{Name: "stale", Path: "old.so"}},
	}

	rootPath := ts.Gw.getBundleDestPath(spec)
	memFs := afero.NewMemMapFs()
	stagePreUnpackedBundle(t, memFs, rootPath, "bundle-a.zip", `{
		"file_list": [],
		"custom_middleware": {"driver": "grpc", "pre": [{"name": "preA", "path": "plugin.so"}]},
		"checksum": "deadbeef", "signature": ""
	}`)
	stagePreUnpackedBundle(t, memFs, rootPath, "bundle-b.zip", `{
		"file_list": [],
		"custom_middleware": {"driver": "grpc", "pre": [{"name": "preB", "path": "plugin.so"}]},
		"checksum": "deadbeef", "signature": ""
	}`)

	require.NoError(t, ts.Gw.loadBundleWithFs(spec, memFs))

	for _, md := range spec.CustomMiddleware.Pre {
		assert.NotEqual(t, "stale", md.Name, "stale middleware must be reset before merge")
	}
	require.Len(t, spec.CustomMiddleware.Pre, 2)
	assert.Equal(t, "preA", spec.CustomMiddleware.Pre[0].Name)
	assert.Equal(t, "preB", spec.CustomMiddleware.Pre[1].Name)
}

// TestLoadBundleWithFs_EmptyBaseURLMultiBundle covers the multi-bundle guard at
// lines 507-509: with two comma-separated names but an empty bundle_base_url,
// loadBundleWithFs must fail closed with "No bundle base URL set". Requires a
// running Redis.
func TestLoadBundleWithFs_EmptyBaseURLMultiBundle(t *testing.T) {
	ts := StartTest(func(c *config.Config) {
		enableLabsMultiBundle(c)
		c.BundleBaseURL = ""
	})
	defer ts.Close()

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:                  "multi-bundle-nobaseurl",
			CustomMiddlewareBundle: "a.zip,b.zip",
		},
	}

	err := ts.Gw.loadBundleWithFs(spec, afero.NewMemMapFs())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "No bundle base URL set")
}

// TestLoadBundleWithFs_PartialFailureFailsClosed covers the fail-closed loop
// exit at lines 524-526 and the fetch-error branch in loadOneBundleForMerge
// (650-651): the first bundle is valid and fetchable over HTTP, the second
// names a bundle that isn't registered (404 on every retry). The overall load
// must error and the error must name the failing bundle. Requires a running
// Redis.
func TestLoadBundleWithFs_PartialFailureFailsClosed(t *testing.T) {
	ts := StartTest(enableLabsMultiBundle)
	defer ts.Close()

	// Shrink retries so the 404 fails fast instead of backing off.
	orig := bundleMaxBackoffRetries
	bundleMaxBackoffRetries = 0
	defer func() { bundleMaxBackoffRetries = orig }()

	bundleA := ts.RegisterBundle("partial_ok_a", mergeBundleManifestJSON("grpc",
		`"pre": [{"name": "PreHookA", "path": "plugin.so"}]`))
	missingB := "does-not-exist-" + "b.zip"

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:                  "multi-bundle-partial",
			CustomMiddlewareBundle: bundleA + "," + missingB,
		},
	}

	err := ts.Gw.loadBundle(spec)
	require.Error(t, err, "a failing second bundle must fail the whole load")
	assert.Contains(t, err.Error(), missingB, "error should name the failing bundle")
}

// TestLoadBundleWithFs_FetchedBadManifestFailsAndCleansUp covers the fetch →
// save → manifest-load failure path in loadOneBundleForMerge (666-670, incl.
// RemoveAll cleanup) and loadBundleManifestNamed's open/decode error branches
// (695-705). Bundle A is valid; bundle B fetches and unzips fine but its
// manifest.json is invalid JSON, so DeepVerify never runs and the load fails
// closed. A second sub-case omits manifest.json entirely (open error).
// Requires a running Redis.
func TestLoadBundleWithFs_FetchedBadManifestFailsAndCleansUp(t *testing.T) {
	t.Run("invalid manifest json", func(t *testing.T) {
		ts := StartTest(enableLabsMultiBundle)
		defer ts.Close()

		bundleA := ts.RegisterBundle("badmanifest_ok_a", mergeBundleManifestJSON("grpc",
			`"pre": [{"name": "PreHookA", "path": "plugin.so"}]`))
		badB := ts.RegisterBundle("badmanifest_bad_b", map[string]string{
			"manifest.json": `{ this is not valid json `,
		})

		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				APIID:                  "multi-bundle-badjson",
				CustomMiddlewareBundle: bundleA + "," + badB,
			},
		}

		err := ts.Gw.loadBundle(spec)
		require.Error(t, err)
		assert.Contains(t, err.Error(), badB)
	})

	t.Run("missing manifest file", func(t *testing.T) {
		ts := StartTest(enableLabsMultiBundle)
		defer ts.Close()

		bundleA := ts.RegisterBundle("nomanifest_ok_a", mergeBundleManifestJSON("grpc",
			`"pre": [{"name": "PreHookA", "path": "plugin.so"}]`))
		// A zip that unpacks a file but has no manifest.json → Open fails.
		noManifestB := ts.RegisterBundle("nomanifest_bad_b", map[string]string{
			"plugin.so": "not-a-manifest",
		})

		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				APIID:                  "multi-bundle-nomanifest",
				CustomMiddlewareBundle: bundleA + "," + noManifestB,
			},
		}

		err := ts.Gw.loadBundle(spec)
		require.Error(t, err)
		assert.Contains(t, err.Error(), noManifestB)
	})
}

// TestFetchBundleByName_BadScheme covers FetchBundleByName's error branches:
// the default "Unknown URL scheme" case (line 350-351) via an ftp base URL, and
// the url.Parse error (line 323-324) via a malformed base URL. Both are reached
// through the multi-bundle path (two names) so the single-bundle fast path is
// bypassed. Requires a running Redis.
func TestFetchBundleByName_BadScheme(t *testing.T) {
	t.Run("unknown scheme", func(t *testing.T) {
		ts := StartTest(func(c *config.Config) {
			enableLabsMultiBundle(c)
			c.BundleBaseURL = "ftp://bundles.local/"
		})
		defer ts.Close()

		spec := &APISpec{APIDefinition: &apidef.APIDefinition{
			APIID:                  "multi-bundle-ftp",
			CustomMiddlewareBundle: "a.zip,b.zip",
		}}
		err := ts.Gw.loadBundleWithFs(spec, afero.NewMemMapFs())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Unknown URL scheme")
	})

	t.Run("malformed base url", func(t *testing.T) {
		ts := StartTest(func(c *config.Config) {
			enableLabsMultiBundle(c)
			c.BundleBaseURL = "://missing-scheme"
		})
		defer ts.Close()

		spec := &APISpec{APIDefinition: &apidef.APIDefinition{
			APIID:                  "multi-bundle-badurl",
			CustomMiddlewareBundle: "a.zip,b.zip",
		}}
		err := ts.Gw.loadBundleWithFs(spec, afero.NewMemMapFs())
		require.Error(t, err)
	})

	t.Run("downloader disabled", func(t *testing.T) {
		// Covers FetchBundleByName's early guard (314-320): with the bundle
		// downloader turned off, a fetch-requiring multi-bundle load fails
		// closed with "Bundle downloader is disabled".
		ts := StartTest(func(c *config.Config) {
			enableLabsMultiBundle(c)
			c.BundleBaseURL = "http://bundles.local/"
			c.EnableBundleDownloader = false
		})
		defer ts.Close()

		spec := &APISpec{APIDefinition: &apidef.APIDefinition{
			APIID:                  "multi-bundle-nodownloader",
			CustomMiddlewareBundle: "a.zip,b.zip",
		}}
		err := ts.Gw.loadBundleWithFs(spec, afero.NewMemMapFs())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Bundle downloader is disabled")
	})
}

// TestMergeBundleManifestIdExtractorFirstWins pins the first-wins IdExtractor
// merge rule at lines 772-774. Sub-case 1: bundle A sets an extractor and bundle
// B sets a different one → A's is kept. Sub-case 2: bundle A sets none and
// bundle B sets one → B's is adopted.
func TestMergeBundleManifestIdExtractorFirstWins(t *testing.T) {
	t.Run("first bundle wins over later", func(t *testing.T) {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}

		a := &apidef.BundleManifest{CustomMiddleware: apidef.MiddlewareSection{
			Driver:      apidef.GrpcDriver,
			IdExtractor: apidef.MiddlewareIdExtractor{ExtractWith: apidef.ValueExtractor},
		}}
		b := &apidef.BundleManifest{CustomMiddleware: apidef.MiddlewareSection{
			Driver:      apidef.GrpcDriver,
			IdExtractor: apidef.MiddlewareIdExtractor{ExtractWith: apidef.RegexExtractor},
		}}

		require.NoError(t, mergeBundleManifest(spec, a, "bundle-a", "bundle-a.zip"))
		require.NoError(t, mergeBundleManifest(spec, b, "bundle-b", "bundle-b.zip"))

		assert.Equal(t, apidef.ValueExtractor, spec.CustomMiddleware.IdExtractor.ExtractWith,
			"first bundle's IdExtractor must win")
	})

	t.Run("later bundle fills when first has none", func(t *testing.T) {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}

		a := &apidef.BundleManifest{CustomMiddleware: apidef.MiddlewareSection{
			Driver: apidef.GrpcDriver,
		}}
		b := &apidef.BundleManifest{CustomMiddleware: apidef.MiddlewareSection{
			Driver:      apidef.GrpcDriver,
			IdExtractor: apidef.MiddlewareIdExtractor{ExtractWith: apidef.RegexExtractor},
		}}

		require.NoError(t, mergeBundleManifest(spec, a, "bundle-a", "bundle-a.zip"))
		require.NoError(t, mergeBundleManifest(spec, b, "bundle-b", "bundle-b.zip"))

		assert.Equal(t, apidef.RegexExtractor, spec.CustomMiddleware.IdExtractor.ExtractWith,
			"second bundle's IdExtractor must be adopted when the first sets none")
	})
}

// TestLoadOneBundleForMerge_OnDiskVerificationFails covers the existing-bundle
// verification-failure path: loadOneBundleForMerge Stats a staged bundle
// (636-643) then loadBundleManifestNamed runs PartialVerify with
// skipVerification=false. The staged manifest declares a signature but a bogus
// checksum, so verification fails (loadBundleManifestNamed 712-717) and
// loadOneBundleForMerge returns a wrapped error naming the bundle (641-643).
// Requires a running Redis.
func TestLoadOneBundleForMerge_OnDiskVerificationFails(t *testing.T) {
	ts := StartTest(func(c *config.Config) {
		enableLabsMultiBundle(c)
		c.BundleBaseURL = "http://bundles.local/"
		c.SkipVerifyExistingPluginBundle = false
	})
	defer ts.Close()

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:                  "multi-bundle-verifyfail",
			CustomMiddlewareBundle: "bad-a.zip,bad-b.zip",
		},
	}
	rootPath := ts.Gw.getBundleDestPath(spec)
	memFs := afero.NewMemMapFs()
	// signature set + wrong checksum → PartialVerify runs and fails.
	stagePreUnpackedBundle(t, memFs, rootPath, "bad-a.zip", `{
		"file_list": [],
		"custom_middleware": {"driver": "grpc", "pre": [{"name": "preA", "path": "plugin.so"}]},
		"checksum": "not-the-real-checksum",
		"signature": "AAAA"
	}`)

	err := ts.Gw.loadBundleWithFs(spec, memFs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad-a.zip")
}

// TestLoadOneBundleForMerge_DriverMismatchOnDisk covers loadOneBundleForMerge's
// merge-error branch (674-676): two on-disk bundles declare different drivers,
// so the second mergeBundleManifest fails driver uniformity and the error is
// wrapped with the offending bundle name. Requires a running Redis.
func TestLoadOneBundleForMerge_DriverMismatchOnDisk(t *testing.T) {
	ts := StartTest(func(c *config.Config) {
		enableLabsMultiBundle(c)
		c.BundleBaseURL = "http://bundles.local/"
		c.SkipVerifyExistingPluginBundle = true
	})
	defer ts.Close()

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:                  "multi-bundle-drivermismatch",
			CustomMiddlewareBundle: "grpc-a.zip,go-b.zip",
		},
	}
	rootPath := ts.Gw.getBundleDestPath(spec)
	memFs := afero.NewMemMapFs()
	stagePreUnpackedBundle(t, memFs, rootPath, "grpc-a.zip", `{
		"file_list": [],
		"custom_middleware": {"driver": "grpc", "pre": [{"name": "preA", "path": "plugin.so"}]},
		"checksum": "deadbeef", "signature": ""
	}`)
	stagePreUnpackedBundle(t, memFs, rootPath, "go-b.zip", `{
		"file_list": [],
		"custom_middleware": {"driver": "goplugin", "pre": [{"name": "preB", "path": "plugin.so"}]},
		"checksum": "deadbeef", "signature": ""
	}`)

	err := ts.Gw.loadBundleWithFs(spec, memFs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "go-b.zip")
	assert.Contains(t, err.Error(), "driver")
}

// TestLoadBundleWithFs_MultiBundleDisabledUsesSingleBundlePath verifies that a
// comma-containing value uses the legacy single-bundle path when the labs flag
// is unset. Requires a running Redis.
func TestLoadBundleWithFs_MultiBundleDisabledUsesSingleBundlePath(t *testing.T) {
	ts := StartTest(func(c *config.Config) {
		c.BundleBaseURL = "http://bundles.local/"
		c.SkipVerifyExistingPluginBundle = true
	})
	defer ts.Close()

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:                  "multi-bundle-disabled",
			CustomMiddlewareBundle: "bundle-a.zip,bundle-b.zip",
		},
	}

	destPath := ts.Gw.getBundleDestPath(spec)
	memFs := afero.NewMemMapFs()
	require.NoError(t, memFs.MkdirAll(destPath, 0755))
	f, err := memFs.Create(filepath.Join(destPath, "manifest.json"))
	require.NoError(t, err)
	_, err = f.WriteString(`{
		"file_list": [],
		"custom_middleware": {"driver": "grpc", "pre": [{"name": "preSingle", "path": "plugin.so"}]},
		"checksum": "deadbeef", "signature": ""
	}`)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	require.NoError(t, ts.Gw.loadBundleWithFs(spec, memFs))
	require.Len(t, spec.CustomMiddleware.Pre, 1)
	assert.Equal(t, "preSingle", spec.CustomMiddleware.Pre[0].Name)
	assert.Equal(t, apidef.GrpcDriver, spec.CustomMiddleware.Driver)
}
