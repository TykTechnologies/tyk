package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/propagation"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/otel"
)

// agentTraceParent — the W3C traceparent an MCP-native agent sets in params._meta.
// Its trace-id (middle field) is what every Tyk record must inherit after the join.
const (
	agentTraceParent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	agentTraceID     = "0af7651916cd43dd8448eb211c80319c"
)

func newMCPTraceMiddleware(t *testing.T, otelEnabled bool) *JSONRPCMiddleware {
	t.Helper()
	conf := config.Config{}
	conf.OpenTelemetry.Enabled = otelEnabled
	conf.OpenTelemetry.SetDefaults()
	gw := NewGateway(conf, context.Background())

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{"tool:get-weather": mcp.ToolPrefix + "get-weather"},
		JSONRPCRouter: mcp.NewRouter(),
	}
	return &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: gw}}
}

func mcpToolsCall(t *testing.T, m *JSONRPCMiddleware, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, code)
	return r
}

// An MCP-native agent (traceparent only in params._meta, no HTTP header) must
// have its trace joined: after ProcessRequest the request context — which every
// later span, access-log line, and audit event reads trace_id from — carries the
// agent's trace_id, not a fresh forked one.
func TestJSONRPCMiddleware_JoinsTraceFromMeta(t *testing.T) {
	m := newMCPTraceMiddleware(t, true)
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get-weather","_meta":{"traceparent":"` + agentTraceParent + `"}},"id":1}`

	r := mcpToolsCall(t, m, body)

	assert.Equal(t, agentTraceID, otel.ExtractTraceID(r.Context()),
		"request context must carry the agent's trace_id after the join")
}

// When the trace context arrives in the HTTP header, Tyk's inbound extraction
// already established it — the body must not fork a second trace from _meta.
func TestJSONRPCMiddleware_HeaderPresent_DoesNotForkFromMeta(t *testing.T) {
	m := newMCPTraceMiddleware(t, true)
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get-weather","_meta":{"traceparent":"00-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-2222222222222222-01"}},"id":1}`

	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("traceparent", agentTraceParent)
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, code)

	// The body's _meta trace-id must NOT have been installed.
	assert.NotEqual(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", otel.ExtractTraceID(r.Context()),
		"a present header must win — no second trace forked from _meta")
}

// With OpenTelemetry disabled the bridge is a no-op and the body is untouched.
func TestJSONRPCMiddleware_TraceJoin_NoOpWhenOTelDisabled(t *testing.T) {
	m := newMCPTraceMiddleware(t, false)
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get-weather","_meta":{"traceparent":"` + agentTraceParent + `"}},"id":1}`

	r := mcpToolsCall(t, m, body)

	assert.Empty(t, otel.ExtractTraceID(r.Context()),
		"no join when tracing is disabled")
}

// With no active trace context the write is a graceful no-op — the forwarded
// body is byte-for-byte unchanged and the request never 500s.
func TestJSONRPCMiddleware_Write_NoOpWithoutContext(t *testing.T) {
	m := newMCPTraceMiddleware(t, true)
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get-weather","arguments":{"city":"London"}},"id":1}`

	r := mcpToolsCall(t, m, body) // no _meta, no header → nothing to write

	got, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	assert.Equal(t, body, string(got), "no trace context ⇒ body forwarded unchanged")
}

// Parity with normal-API upstream propagation: whenever OTel is on, Tyk's active
// trace context is written into the outbound params._meta so the MCP server —
// which reads the body, not the header — joins the trace. No per-API opt-in.
func TestJSONRPCMiddleware_Write_InjectsTykContextIntoMeta(t *testing.T) {
	const tykTraceParent = "00-cccccccccccccccccccccccccccccccc-3333333333333333-01"
	m := newMCPTraceMiddleware(t, true)
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get-weather"},"id":1}`

	// Seed the request context with Tyk's trace context (no _meta, no header on the wire).
	ctx := propagation.TraceContext{}.Extract(context.Background(),
		propagation.MapCarrier{"traceparent": tykTraceParent})
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, code)

	out, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	tc, ok := mcp.ReadMetaTraceContext(out)
	require.True(t, ok, "outbound body must now carry params._meta trace context")
	assert.Equal(t, tykTraceParent, tc.TraceParent, "the MCP server receives Tyk's trace context")
}
