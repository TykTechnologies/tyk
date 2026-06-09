package otel

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/propagation"

	otelmcp "github.com/TykTechnologies/tyk/internal/otel/mcp"
)

// injectCurrent serialises the request context's active trace context back into
// a carrier, so a test can confirm what the join installed.
func injectCurrent(r *http.Request) propagation.MapCarrier {
	carrier := propagation.MapCarrier{}
	propagation.TraceContext{}.Inject(r.Context(), carrier)
	return carrier
}

// traceparent "00-<32hex traceid>-<16hex spanid>-01" → traceid is the middle field.
const (
	traceIDFromM = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestJoinMCPTraceContext(t *testing.T) {
	t.Parallel()
	sources := DefaultMCPReadSources()

	t.Run("meta-only request joins the agent trace, so ExtractTraceID returns it", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/mcp", nil) // no traceparent header
		source := JoinMCPTraceContext(r, sources, metaBody(traceParentM))

		assert.Equal(t, otelmcp.TraceSourceMeta, source)
		assert.Equal(t, traceIDFromM, ExtractTraceID(r.Context()),
			"after the join every later read of the request context sees the agent trace_id")
	})

	t.Run("header present: no join, context left as-is (reconcile, don't fork)", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		r.Header.Set("traceparent", traceParentH)
		source := JoinMCPTraceContext(r, sources, metaBody(traceParentM))

		assert.Equal(t, otelmcp.TraceSourceBoth, source)
		assert.Empty(t, ExtractTraceID(r.Context()),
			"join must not install a body context when the header already carried one")
	})

	t.Run("no trace context anywhere: nothing installed", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		source := JoinMCPTraceContext(r, sources, []byte(`{"method":"tools/call","params":{"name":"x"}}`))

		assert.Equal(t, otelmcp.TraceSourceNone, source)
		assert.Empty(t, ExtractTraceID(r.Context()))
	})

	t.Run("tracestate carried through the join", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"_meta":{"traceparent":"` + traceParentM + `","tracestate":"vendor=1"}}}`)
		r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		JoinMCPTraceContext(r, sources, body)

		// Re-inject the joined context and confirm tracestate survived.
		carrier := injectCurrent(r)
		assert.Equal(t, traceParentM, carrier["traceparent"])
		assert.Equal(t, "vendor=1", carrier["tracestate"])
	})
}
