package otel

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/mcp"
)

const (
	traceParentH = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-1111111111111111-01"
	traceParentM = "00-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-2222222222222222-01"
)

func metaBody(tp string) []byte {
	return []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","_meta":{"traceparent":"` + tp + `"}}}`)
}

func TestResolveMCPTraceContext(t *testing.T) {
	t.Parallel()
	sources := DefaultMCPReadSources()

	t.Run("meta-only: join the body context", func(t *testing.T) {
		// MCP-native agent — no HTTP header, traceparent only in params._meta.
		res := ResolveMCPTraceContext(sources, "", metaBody(traceParentM))
		assert.True(t, res.JoinFromBody, "header absent + body present ⇒ Tyk must join")
		assert.Equal(t, traceParentM, res.Context.TraceParent)
		assert.Equal(t, mcp.TraceSourceMeta, res.Source)
	})

	t.Run("header-only: reconcile, never fork", func(t *testing.T) {
		res := ResolveMCPTraceContext(sources, traceParentH, []byte(`{"method":"tools/call","params":{"name":"x"}}`))
		assert.False(t, res.JoinFromBody, "header already established the trace")
		assert.Equal(t, mcp.TraceSourceHeader, res.Source)
	})

	t.Run("both present: header authoritative, no second trace", func(t *testing.T) {
		// Header H and meta M differ; default order has header first → H wins,
		// and because the inbound extraction already used H we do NOT re-join.
		res := ResolveMCPTraceContext(sources, traceParentH, metaBody(traceParentM))
		assert.False(t, res.JoinFromBody, "both channels present ⇒ reconcile to header, don't fork")
		assert.Equal(t, mcp.TraceSourceBoth, res.Source)
	})

	t.Run("neither present: nothing to join", func(t *testing.T) {
		res := ResolveMCPTraceContext(sources, "", []byte(`{"method":"tools/call","params":{"name":"x"}}`))
		assert.False(t, res.JoinFromBody)
		assert.Equal(t, mcp.TraceSourceNone, res.Source)
	})

	t.Run("configured body path drives the body read", func(t *testing.T) {
		// traceparent at top-level "meta"; only a source pointing there resolves it.
		body := []byte(`{"jsonrpc":"2.0","method":"tools/call","meta":{"traceparent":"` + traceParentM + `"},"params":{"name":"x"}}`)

		def := ResolveMCPTraceContext(DefaultMCPReadSources(), "", body)
		assert.False(t, def.JoinFromBody, "default path params._meta must not resolve the moved location")

		custom := ResolveMCPTraceContext([]MCPTraceSource{{Channel: MCPTraceChannelBody, Path: "meta"}}, "", body)
		assert.True(t, custom.JoinFromBody, "configured path resolves the body context")
		assert.Equal(t, traceParentM, custom.Context.TraceParent)
	})

	t.Run("first body source wins precedence", func(t *testing.T) {
		// Two body sources; the first one that resolves wins.
		body := []byte(`{"jsonrpc":"2.0","method":"tools/call","meta":{"traceparent":"` + traceParentH + `"},"params":{"_meta":{"traceparent":"` + traceParentM + `"}}}`)
		sources := []MCPTraceSource{
			{Channel: MCPTraceChannelBody, Path: "meta"},
			{Channel: MCPTraceChannelBody, Path: "params._meta"},
		}
		res := ResolveMCPTraceContext(sources, "", body)
		assert.True(t, res.JoinFromBody)
		assert.Equal(t, traceParentH, res.Context.TraceParent, "first matching body source wins")
	})
}
