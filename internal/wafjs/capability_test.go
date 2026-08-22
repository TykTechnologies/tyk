package wafjs

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/dop251/goja"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The complete ECMAScript surface a fresh runtime of the pinned goja
// exposes (goja builtin_global.go createGlobalObjectTemplate plus the typed
// array template). The WAF host adds only the two ABI names below.
var allowedRuntimeGlobals = []string{
	"AggregateError", "ArrayBuffer", "Array", "BigInt", "BigInt64Array",
	"BigUint64Array", "Boolean", "DataView", "Date", "Error", "EvalError",
	"Float32Array", "Float64Array", "Function", "GoError", "Infinity",
	"Int16Array", "Int32Array", "Int8Array", "JSON", "Map", "Math", "NaN",
	"Number", "Object", "Promise", "Proxy", "RangeError", "ReferenceError",
	"Reflect", "RegExp", "Set", "String", "Symbol", "SyntaxError",
	"TypeError", "URIError", "Uint16Array", "Uint32Array", "Uint8Array",
	"Uint8ClampedArray", "WeakMap", "WeakSet",
	"decodeURI", "decodeURIComponent", "encodeURI", "encodeURIComponent",
	"escape", "eval", "globalThis", "isFinite", "isNaN", "parseFloat",
	"parseInt", "undefined", "unescape",
	entryPointName, rulesetBindingName,
}

// Capability names the runtime must never expose: Tyk plugin APIs, network,
// filesystem, process, timer, storage, and the recorded engine gaps
// (TextDecoder/TextEncoder are absent at the pin per the capability map).
var forbiddenRuntimeGlobals = []string{
	// Tyk plugin and middleware APIs.
	"TykJS", "Tyk", "LOG", "LOG_DATA", "rawLog", "store", "__plugin_db",
	// Node-style module system and process.
	"require", "module", "exports", "process", "Buffer", "global",
	"__dirname", "__filename", "child_process", "exec", "spawn",
	// Filesystem and OS.
	"fs", "os", "path", "readFile", "writeFile",
	// Network.
	"fetch", "XMLHttpRequest", "WebSocket", "http", "https", "net", "dns",
	// Timers and scheduling.
	"setTimeout", "setInterval", "setImmediate", "clearTimeout",
	"clearInterval", "clearImmediate", "queueMicrotask",
	// Storage and browser APIs.
	"localStorage", "sessionStorage", "indexedDB", "document", "window",
	"postMessage", "Worker", "console",
	// Shared memory.
	"SharedArrayBuffer", "Atomics",
	// Recorded absent engine capabilities.
	"TextDecoder", "TextEncoder",
}

// TestRuntimeExposesNoHostCapability asserts the WAF-owned runtime exposes
// no plugin, network, filesystem, process, timer, or storage API: the exact
// global surface equals the ECMAScript allow-list plus the two WAF ABI names.
func TestRuntimeExposesNoHostCapability(t *testing.T) {
	h := NewHost()
	require.NoError(t, h.Build(context.Background(), fixtureConfig(t)))

	st := h.state.Load()
	require.NotNil(t, st)
	vm, err := st.newVM()
	require.NoError(t, err)

	namesValue, err := vm.RunString("Object.getOwnPropertyNames(globalThis).sort().join(',')")
	require.NoError(t, err)
	got := strings.Split(namesValue.String(), ",")
	slices.Sort(got)

	expected := slices.Clone(allowedRuntimeGlobals)
	slices.Sort(expected)

	assert.Equal(t, expected, got,
		"the runtime surface changed; any addition must pass the capability-map decision rule")

	for _, banned := range forbiddenRuntimeGlobals {
		assert.NotContains(t, got, banned,
			"the runtime must not expose %q to engine code", banned)
	}
}

// TestRuntimeBindsABIForInspection asserts the built state's runtime carries
// the bound ruleset and the callable inspection entry point.
func TestRuntimeBindsABIForInspection(t *testing.T) {
	h := NewHost()
	require.NoError(t, h.Build(context.Background(), fixtureConfig(t)))

	st := h.state.Load()
	require.NotNil(t, st)
	vm, err := st.newVM()
	require.NoError(t, err)

	value, err := vm.RunString("JSON.stringify(globalThis." + rulesetBindingName + ")")
	require.NoError(t, err)
	assert.Contains(t, value.String(), `"id":"920100"`,
		"the ruleset payload must reach the runtime")

	entry, ok := goja.AssertFunction(vm.Get(entryPointName))
	require.True(t, ok, "the engine entry point must be callable")
	_, err = entry(goja.Undefined(), vm.NewObject(), vm.NewObject())
	require.NoError(t, err)
}
