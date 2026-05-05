package gateway

import (
	"testing"

	"github.com/dop251/goja"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// TestGojaHandlerAliasIsDeterministic locks in the contract that AliasFor
// produces the same alias for the same (path, name) inputs every time. The
// dispatch path relies on this — both load-time wrap and runtime lookup
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
