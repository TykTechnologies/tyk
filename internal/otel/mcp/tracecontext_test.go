package mcp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleTraceParent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

func TestReadMetaTraceContext(t *testing.T) {
	t.Parallel()

	t.Run("reads traceparent and tracestate from params._meta", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"lookup","_meta":{"traceparent":"` + sampleTraceParent + `","tracestate":"vendor=1"}}}`)
		tc, ok := ReadMetaTraceContext(body)
		require.True(t, ok)
		assert.Equal(t, sampleTraceParent, tc.TraceParent)
		assert.Equal(t, "vendor=1", tc.TraceState)
		assert.True(t, tc.Valid())
	})

	t.Run("no-op when params._meta absent", func(t *testing.T) {
		_, ok := ReadMetaTraceContext([]byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"lookup"}}`))
		assert.False(t, ok)
	})

	t.Run("no-op on non-JSON and malformed", func(t *testing.T) {
		for _, b := range [][]byte{nil, []byte(``), []byte(`not json`), []byte(`{"params":`)} {
			_, ok := ReadMetaTraceContext(b)
			assert.False(t, ok)
		}
	})
}

// ReadBodyTraceContext drives the configurable read_sources `body` channel: the
// reserved W3C key names stay fixed, only the object location (dotted path) moves.
func TestReadBodyTraceContext(t *testing.T) {
	t.Parallel()

	t.Run("default path params._meta resolves the MCP-spec location", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"lookup","_meta":{"traceparent":"` + sampleTraceParent + `","tracestate":"vendor=1"}}}`)
		tc, ok := ReadBodyTraceContext(body, "params._meta")
		require.True(t, ok)
		assert.Equal(t, sampleTraceParent, tc.TraceParent)
		assert.Equal(t, "vendor=1", tc.TraceState)
	})

	t.Run("configured top-level path is honoured, default path is not", func(t *testing.T) {
		// traceparent lives at top-level "meta", not params._meta.
		body := []byte(`{"jsonrpc":"2.0","method":"tools/call","meta":{"traceparent":"` + sampleTraceParent + `"},"params":{"name":"lookup"}}`)

		tc, ok := ReadBodyTraceContext(body, "meta")
		require.True(t, ok, "configured path must resolve")
		assert.Equal(t, sampleTraceParent, tc.TraceParent)

		_, ok = ReadBodyTraceContext(body, "params._meta")
		assert.False(t, ok, "default path must NOT resolve — the location moved")
	})

	t.Run("no-op when the configured path is absent", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"lookup"}}`)
		_, ok := ReadBodyTraceContext(body, "params._meta")
		assert.False(t, ok)
	})

	t.Run("no-op on non-JSON, empty path, and malformed", func(t *testing.T) {
		for _, b := range [][]byte{nil, []byte(``), []byte(`not json`)} {
			_, ok := ReadBodyTraceContext(b, "params._meta")
			assert.False(t, ok)
		}
		_, ok := ReadBodyTraceContext([]byte(`{"method":"x","params":{"_meta":{"traceparent":"`+sampleTraceParent+`"}}}`), "")
		assert.False(t, ok, "empty path resolves nothing")
	})
}

func TestWriteMetaTraceContext_PreservesEveryOtherField(t *testing.T) {
	t.Parallel()

	body := []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"lookup","arguments":{"customer_id":"c-1","nested":{"a":[1,2,3]}}}}`)
	out, changed := WriteMetaTraceContext(body, TraceContext{TraceParent: sampleTraceParent})
	require.True(t, changed)

	// _meta now carries the traceparent.
	tc, ok := ReadMetaTraceContext(out)
	require.True(t, ok)
	assert.Equal(t, sampleTraceParent, tc.TraceParent)

	// Every other field round-trips by value (key order may differ).
	var before, after map[string]any
	require.NoError(t, json.Unmarshal(body, &before))
	require.NoError(t, json.Unmarshal(out, &after))
	assert.Equal(t, before["jsonrpc"], after["jsonrpc"])
	assert.Equal(t, before["id"], after["id"])
	assert.Equal(t, before["method"], after["method"])

	beforeArgs := before["params"].(map[string]any)["arguments"]
	afterArgs := after["params"].(map[string]any)["arguments"]
	assert.Equal(t, beforeArgs, afterArgs, "arguments must be preserved exactly")
	assert.Equal(t, "lookup", after["params"].(map[string]any)["name"])
}

func TestWriteMetaTraceContext_CarriesTraceState(t *testing.T) {
	t.Parallel()

	out, changed := WriteMetaTraceContext(
		[]byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"lookup"}}`),
		TraceContext{TraceParent: sampleTraceParent, TraceState: "vendor=1"},
	)
	require.True(t, changed)
	tc, ok := ReadMetaTraceContext(out)
	require.True(t, ok)
	assert.Equal(t, sampleTraceParent, tc.TraceParent)
	assert.Equal(t, "vendor=1", tc.TraceState, "write must forward the full W3C context, not just traceparent")
}

func TestWriteMetaTraceContext_PreservesExistingMetaKeys(t *testing.T) {
	t.Parallel()

	// A pre-existing, unrelated _meta key (e.g. baggage) must survive the write.
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"lookup","_meta":{"baggage":"k=v"}}}`)
	out, changed := WriteMetaTraceContext(body, TraceContext{TraceParent: sampleTraceParent})
	require.True(t, changed)

	var after map[string]any
	require.NoError(t, json.Unmarshal(out, &after))
	meta := after["params"].(map[string]any)["_meta"].(map[string]any)
	assert.Equal(t, "k=v", meta["baggage"], "unrelated _meta keys must be preserved")
	assert.Equal(t, sampleTraceParent, meta["traceparent"])
}

func TestWriteMetaTraceContext_CreatesParamsAndMetaWhenAbsent(t *testing.T) {
	t.Parallel()

	// No params at all → params._meta is created.
	out, changed := WriteMetaTraceContext([]byte(`{"jsonrpc":"2.0","method":"initialize"}`), TraceContext{TraceParent: sampleTraceParent})
	require.True(t, changed)
	tc, ok := ReadMetaTraceContext(out)
	require.True(t, ok)
	assert.Equal(t, sampleTraceParent, tc.TraceParent)
}

func TestWriteMetaTraceContext_NoOps(t *testing.T) {
	t.Parallel()

	t.Run("invalid trace context leaves body unchanged", func(t *testing.T) {
		body := []byte(`{"method":"tools/call","params":{}}`)
		out, changed := WriteMetaTraceContext(body, TraceContext{})
		assert.False(t, changed)
		assert.Equal(t, body, out)
	})

	t.Run("non-MCP json (no method) is untouched", func(t *testing.T) {
		body := []byte(`{"hello":"world"}`)
		out, changed := WriteMetaTraceContext(body, TraceContext{TraceParent: sampleTraceParent})
		assert.False(t, changed)
		assert.Equal(t, body, out)
	})

	t.Run("malformed body is untouched", func(t *testing.T) {
		body := []byte(`{not json`)
		out, changed := WriteMetaTraceContext(body, TraceContext{TraceParent: sampleTraceParent})
		assert.False(t, changed)
		assert.Equal(t, body, out)
	})
}

func TestClassifyTraceSource(t *testing.T) {
	t.Parallel()
	assert.Equal(t, TraceSourceNone, ClassifyTraceSource("", false))
	assert.Equal(t, TraceSourceHeader, ClassifyTraceSource(sampleTraceParent, false))
	assert.Equal(t, TraceSourceMeta, ClassifyTraceSource("", true))
	assert.Equal(t, TraceSourceBoth, ClassifyTraceSource(sampleTraceParent, true))
}
