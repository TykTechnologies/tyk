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

// TestMergeBundleManifestAppendsHooks verifies the multi-bundle merge
// concatenates every array hook (pre/post/post_key_auth/response) in
// declaration order across bundles and within each bundle, and that each
// entry's Path is prefixed with the bundle's subdir so api_loader's
// prefix-join resolves to the correct file.
func TestMergeBundleManifestAppendsHooks(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}

	// Two entries per hook in bundle A so that within-bundle order is also
	// asserted, not just A-before-B order.
	a := &apidef.BundleManifest{
		CustomMiddleware: apidef.MiddlewareSection{
			Driver: apidef.OttoDriver,
			Pre: []apidef.MiddlewareDefinition{
				{Name: "preA1", Path: "plugin.js"},
				{Name: "preA2", Path: "plugin.js"},
			},
			Post: []apidef.MiddlewareDefinition{
				{Name: "postA1", Path: "plugin.js"},
			},
			PostKeyAuth: []apidef.MiddlewareDefinition{
				{Name: "pkaA1", Path: "plugin.js"},
			},
		},
	}
	b := &apidef.BundleManifest{
		CustomMiddleware: apidef.MiddlewareSection{
			Driver: apidef.OttoDriver,
			Pre: []apidef.MiddlewareDefinition{
				{Name: "preB1", Path: "plugin.js"},
			},
			PostKeyAuth: []apidef.MiddlewareDefinition{
				{Name: "pkaB1", Path: "plugin.js"},
				{Name: "pkaB2", Path: "plugin.js"},
			},
			Response: []apidef.MiddlewareDefinition{
				{Name: "respB1", Path: "plugin.js"},
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

	// post_key_auth: A's one then B's two (the hook type used by real
	// auth-aware plugins and previously not covered).
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
	assert.Equal(t, apidef.OttoDriver, spec.CustomMiddleware.Driver)
}

// TestMergeBundleManifestRejectsDuplicateAuthCheck enforces the rule that
// only one bundle may declare an auth_check hook per API.
func TestMergeBundleManifestRejectsDuplicateAuthCheck(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}

	a := &apidef.BundleManifest{
		CustomMiddleware: apidef.MiddlewareSection{
			Driver:    apidef.OttoDriver,
			AuthCheck: apidef.MiddlewareDefinition{Name: "authA", Path: "plugin.js"},
		},
	}
	b := &apidef.BundleManifest{
		CustomMiddleware: apidef.MiddlewareSection{
			Driver:    apidef.OttoDriver,
			AuthCheck: apidef.MiddlewareDefinition{Name: "authB", Path: "plugin.js"},
		},
	}

	require.NoError(t, mergeBundleManifest(spec, a, "bundle-a", "bundle-a.zip"))
	err := mergeBundleManifest(spec, b, "bundle-b", "bundle-b.zip")
	require.Error(t, err, "second auth_check must be rejected")
	assert.Contains(t, err.Error(), "auth_check")
}

// TestMergeBundleManifestRejectsDriverMismatch enforces driver uniformity
// across composed bundles.
func TestMergeBundleManifestRejectsDriverMismatch(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}

	a := &apidef.BundleManifest{
		CustomMiddleware: apidef.MiddlewareSection{Driver: apidef.OttoDriver},
	}
	b := &apidef.BundleManifest{
		CustomMiddleware: apidef.MiddlewareSection{Driver: apidef.PythonDriver},
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
	assert.NotEmpty(t, bundleSubdirName("")) // fallback hash path
}

// TestLoadBundleWithFs_EarlyReturns covers the three short-circuit branches
// at the top of loadBundleWithFs: management node, bundle explicitly disabled,
// and empty CustomMiddlewareBundle (which is the no-bundles case after the
// parseBundleNames refactor). All three must return nil without touching the
// filesystem.
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

// TestLoadBundleWithFs_CommaSeparatedMergesBothBundles wires the end-to-end
// selection rule: a comma-separated CustomMiddlewareBundle value enters the
// merge path (not the legacy single-bundle path) and produces a spec whose
// CustomMiddleware section holds hooks from every named bundle, each with
// its per-bundle subdir prefix. Both bundles are pre-staged on the in-memory
// FS so loadOneBundleForMerge takes the "existing bundle" branch and we can
// skip signature verification with SkipVerifyExistingPluginBundle.
func TestLoadBundleWithFs_CommaSeparatedMergesBothBundles(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.BundleBaseURL = "http://bundles.local/"
		globalConf.SkipVerifyExistingPluginBundle = true
	})
	defer ts.Close()

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:                  "multi-bundle-e2e",
			CustomMiddlewareBundle: "bundle-a.zip,bundle-b.zip",
		},
	}

	rootPath := ts.Gw.getBundleDestPath(spec)
	subdirA := bundleSubdirName("bundle-a.zip")
	subdirB := bundleSubdirName("bundle-b.zip")

	memFs := afero.NewMemMapFs()
	require.NoError(t, memFs.MkdirAll(filepath.Join(rootPath, subdirA), 0755))
	require.NoError(t, memFs.MkdirAll(filepath.Join(rootPath, subdirB), 0755))

	// Bundle A: one pre hook + one post hook.
	manifestA, err := memFs.Create(filepath.Join(rootPath, subdirA, "manifest.json"))
	require.NoError(t, err)
	_, err = manifestA.WriteString(`{
		"file_list": ["plugin.js"],
		"custom_middleware": {
			"driver": "otto",
			"pre":  [{"name": "preA",  "path": "plugin.js"}],
			"post": [{"name": "postA", "path": "plugin.js"}]
		},
		"checksum": "deadbeef",
		"signature": ""
	}`)
	require.NoError(t, err)
	require.NoError(t, manifestA.Close())

	// Bundle B: one pre hook + one response hook.
	manifestB, err := memFs.Create(filepath.Join(rootPath, subdirB, "manifest.json"))
	require.NoError(t, err)
	_, err = manifestB.WriteString(`{
		"file_list": ["plugin.js"],
		"custom_middleware": {
			"driver": "otto",
			"pre":      [{"name": "preB",      "path": "plugin.js"}],
			"response": [{"name": "responseB", "path": "plugin.js"}]
		},
		"checksum": "deadbeef",
		"signature": ""
	}`)
	require.NoError(t, err)
	require.NoError(t, manifestB.Close())

	require.NoError(t, ts.Gw.loadBundleWithFs(spec, memFs))

	// pre: A first, B second.
	require.Len(t, spec.CustomMiddleware.Pre, 2)
	assert.Equal(t, "preA", spec.CustomMiddleware.Pre[0].Name)
	assert.True(t, strings.HasPrefix(spec.CustomMiddleware.Pre[0].Path, subdirA))
	assert.Equal(t, "preB", spec.CustomMiddleware.Pre[1].Name)
	assert.True(t, strings.HasPrefix(spec.CustomMiddleware.Pre[1].Path, subdirB))

	// post: only from A.
	require.Len(t, spec.CustomMiddleware.Post, 1)
	assert.Equal(t, "postA", spec.CustomMiddleware.Post[0].Name)
	assert.True(t, strings.HasPrefix(spec.CustomMiddleware.Post[0].Path, subdirA))

	// response: only from B.
	require.Len(t, spec.CustomMiddleware.Response, 1)
	assert.Equal(t, "responseB", spec.CustomMiddleware.Response[0].Name)
	assert.True(t, strings.HasPrefix(spec.CustomMiddleware.Response[0].Path, subdirB))

	// Uniform driver propagated.
	assert.Equal(t, apidef.OttoDriver, spec.CustomMiddleware.Driver)
}

// TestParseBundleNames locks the comma-separated CustomMiddlewareBundle
// contract: a bare name parses to one entry, whitespace is trimmed, empty
// segments are dropped, and a blank input yields nil.
func TestParseBundleNames(t *testing.T) {
	assert.Nil(t, parseBundleNames(""))
	assert.Equal(t, []string{"a.zip"}, parseBundleNames("a.zip"))
	assert.Equal(t, []string{"a.zip", "b.zip"}, parseBundleNames("a.zip,b.zip"))
	assert.Equal(t, []string{"a.zip", "b.zip"}, parseBundleNames(" a.zip , b.zip "))
	assert.Equal(t, []string{"a.zip"}, parseBundleNames("a.zip,"))
	assert.Nil(t, parseBundleNames(", , "))
}
