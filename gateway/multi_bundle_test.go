package gateway

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/dop251/goja"
	"github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

// TestGojaHandlerAliasIsDeterministic locks in the contract that AliasFor
// produces the same alias for the same (path, name) inputs every time. The
// dispatch path relies on this — both load-time rebrand and runtime lookup
// must agree on the global identifier.
func TestGojaHandlerAliasIsDeterministic(t *testing.T) {
	a1 := gojaHandlerAlias("/tmp/bundles/abc/plugin.js", "handler")
	a2 := gojaHandlerAlias("/tmp/bundles/abc/plugin.js", "handler")
	assert.Equal(t, a1, a2, "alias must be deterministic for the same inputs")

	// Different paths must produce different aliases (this is the whole point).
	a3 := gojaHandlerAlias("/tmp/bundles/xyz/plugin.js", "handler")
	assert.NotEqual(t, a1, a3, "different paths must rebrand differently")

	// Different names under the same path must also differ.
	a4 := gojaHandlerAlias("/tmp/bundles/abc/plugin.js", "responseHandler")
	assert.NotEqual(t, a1, a4, "different names must rebrand differently")

	// Aliases must be JS-safe identifiers.
	assert.Regexp(t, `^__tyk_h_[0-9a-f]+_[A-Za-z0-9_]+$`, a1, "alias must be a legal JS identifier")
}

// TestGojaIIFEIsolatesMultiFileHandlers verifies the latent multi-file
// handler collision is fixed: two compiled programs both declaring
// `var handler = ...` no longer overwrite each other inside the JSVM. The
// IIFE wrap inserted by wrapMiddlewareSource keeps each plugin's vars local
// to its closure and exposes only the per-(path, name) alias on globalThis.
//
// This is the test that proves PR #1's correctness for multi-file bundles
// and the prerequisite for multi-bundle composition (PR #2).
func TestGojaIIFEIsolatesMultiFileHandlers(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.APIID = "rebrand-test"
		spec.CustomMiddleware.Driver = apidef.JavaScriptDriver
	})[0]

	jsvm := &GojaJSVM{}
	jsvm.Init(spec, logrus.NewEntry(log), g.Gw)
	require.True(t, jsvm.Initialized())

	// Two programs, both declaring `var handler = ...`. Without isolation,
	// the second's `var handler` would overwrite the first's global.
	const fileA = "/virtual/a.js"
	const fileB = "/virtual/b.js"
	srcA := `var handler = "from-a";`
	srcB := `var handler = "from-b";`

	require.NoError(t, jsvm.LoadInlineMiddleware(fileA, srcA, []string{"handler"}))
	require.NoError(t, jsvm.LoadInlineMiddleware(fileB, srcB, []string{"handler"}))

	aliasA := jsvm.AliasFor(fileA, "handler")
	aliasB := jsvm.AliasFor(fileB, "handler")
	assert.NotEqual(t, aliasA, aliasB, "aliases for distinct files must differ")

	vm := jsvm.newRuntime()

	// Both aliases reachable, each holding its own file's value.
	gotA, err := vm.RunString(aliasA + ";")
	require.NoError(t, err)
	assert.Equal(t, "from-a", gotA.String(), "alias A must hold A's handler value")

	gotB, err := vm.RunString(aliasB + ";")
	require.NoError(t, err)
	assert.Equal(t, "from-b", gotB.String(), "alias B must hold B's handler value")

	// The original `handler` global must NOT exist on globalThis — the IIFE
	// wrap keeps it local to each plugin's closure.
	gotOriginal := vm.Get("handler")
	assert.True(t, gotOriginal == nil || goja.IsUndefined(gotOriginal),
		"original `handler` global must not leak to globalThis; got %v", gotOriginal)
}

// TestGojaIIFEPreservesClosureCaptures verifies that closures inside a
// plugin's source — which reference the plugin's `var handler` lexically —
// keep working after the IIFE wrap. This is the property that capture-and-
// clear strategies break: clearing the global breaks the closure's binding.
// IIFE wrap preserves the local binding because the var is local.
func TestGojaIIFEPreservesClosureCaptures(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.APIID = "closure-test"
		spec.CustomMiddleware.Driver = apidef.JavaScriptDriver
	})[0]

	jsvm := &GojaJSVM{}
	jsvm.Init(spec, logrus.NewEntry(log), g.Gw)

	// `handler` is referenced inside its own callback — exactly the pattern
	// real plugins use (e.g. `handler.NewProcessRequest(function(){ ... handler.ReturnData(...) })`).
	const path = "/virtual/closure.js"
	src := `
var handler = {
    name: "real-handler",
    invoke: function() { return handler.name; }
};`
	require.NoError(t, jsvm.LoadInlineMiddleware(path, src, []string{"handler"}))

	alias := jsvm.AliasFor(path, "handler")
	vm := jsvm.newRuntime()

	got, err := vm.RunString(alias + ".invoke();")
	require.NoError(t, err)
	assert.Equal(t, "real-handler", got.String(), "closure must still resolve `handler` lexically inside the IIFE")
}

// TestGojaRebrandSkipsNonMiddlewarePrograms ensures that programs without
// registered aliases (coreJS, TykJsResponse, user TykJSPath libraries) keep
// their globals intact. The rebrand mechanism must not mangle anything it
// doesn't own.
func TestGojaRebrandSkipsNonMiddlewarePrograms(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.APIID = "no-rebrand-test"
		spec.CustomMiddleware.Driver = apidef.JavaScriptDriver
	})[0]

	jsvm := &GojaJSVM{}
	jsvm.Init(spec, logrus.NewEntry(log), g.Gw)

	// LoadScript registers no aliases — it's the "support code" path.
	require.NoError(t, jsvm.LoadScript(`var supportLib = "still-here";`))

	vm := jsvm.newRuntime()

	got, err := vm.RunString(`supportLib;`)
	require.NoError(t, err)
	assert.Equal(t, "still-here", got.String(), "unaliased globals must survive replay")
}

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
			Driver: apidef.JavaScriptDriver,
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
			Driver: apidef.JavaScriptDriver,
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
	assert.Equal(t, apidef.JavaScriptDriver, spec.CustomMiddleware.Driver)
}

// TestMergeBundleManifestPreservesInlineCode verifies that middleware
// definitions carrying inline Code (with empty Path) survive the merge
// unchanged — no spurious subdir prefix is prepended to an empty Path,
// and the Code payload reaches the merged section verbatim. This is the
// v1 Plugin Studio hot path.
func TestMergeBundleManifestPreservesInlineCode(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}

	const inlineSrc = "dmFyIHg9MTsK" // "var x=1;\n" base64

	manifest := &apidef.BundleManifest{
		CustomMiddleware: apidef.MiddlewareSection{
			Driver: apidef.JavaScriptDriver,
			Pre: []apidef.MiddlewareDefinition{
				{Name: "inlineHandler", Code: inlineSrc},                 // inline, no Path
				{Name: "fileHandler", Path: "plugin.js"},                  // file-mounted, gets prefixed
				{Name: "mixedHandler", Path: "plugin.js", Code: inlineSrc}, // both — Path still rewrites
			},
		},
	}

	require.NoError(t, mergeBundleManifest(spec, manifest, "bundle-a", "bundle-a.zip"))

	require.Len(t, spec.CustomMiddleware.Pre, 3)

	// Inline-only: Path remains empty (no "bundle-a/" prefix on nothing),
	// Code passes through verbatim.
	assert.Empty(t, spec.CustomMiddleware.Pre[0].Path, "inline-Code entry must not get a subdir prefix on empty Path")
	assert.Equal(t, inlineSrc, spec.CustomMiddleware.Pre[0].Code)

	// File-only: Path gets the subdir prefix as usual.
	assert.True(t, strings.HasPrefix(spec.CustomMiddleware.Pre[1].Path, "bundle-a"))
	assert.Empty(t, spec.CustomMiddleware.Pre[1].Code)

	// Mixed: Path still rewrites, Code still passes through. The Code field
	// takes precedence at execution time, but the merge step doesn't pick a
	// side — both fields survive intact.
	assert.True(t, strings.HasPrefix(spec.CustomMiddleware.Pre[2].Path, "bundle-a"))
	assert.Equal(t, inlineSrc, spec.CustomMiddleware.Pre[2].Code)
}

// TestMergeBundleManifestRejectsDuplicateAuthCheck enforces the rule that
// only one bundle may declare an auth_check hook per API.
func TestMergeBundleManifestRejectsDuplicateAuthCheck(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}

	a := &apidef.BundleManifest{
		CustomMiddleware: apidef.MiddlewareSection{
			Driver:    apidef.JavaScriptDriver,
			AuthCheck: apidef.MiddlewareDefinition{Name: "authA", Path: "plugin.js"},
		},
	}
	b := &apidef.BundleManifest{
		CustomMiddleware: apidef.MiddlewareSection{
			Driver:    apidef.JavaScriptDriver,
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
		CustomMiddleware: apidef.MiddlewareSection{Driver: apidef.JavaScriptDriver},
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
			"driver": "javascript",
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
			"driver": "javascript",
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
	assert.Equal(t, apidef.JavaScriptDriver, spec.CustomMiddleware.Driver)
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
