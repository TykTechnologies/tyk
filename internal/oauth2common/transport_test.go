package oauth2common

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// TestNewIdPHTTPClient_EmitsChildClientSpan pins TC11: when the request context
// carries an active span, the IdP round-trip is emitted as a child client span
// nested under the parent. otelhttp builds the span from the propagated
// context — no manual span code in the exchange path.
func TestNewIdPHTTPClient_EmitsChildClientSpan(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	ctx, parent := tp.Tracer("test").Start(context.Background(), "parent")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, nil)
	require.NoError(t, err)

	resp, err := NewIdPHTTPClient(5 * time.Second).Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	parent.End()

	var client sdktrace.ReadOnlySpan
	for _, s := range sr.Ended() {
		if s.SpanKind() == oteltrace.SpanKindClient {
			client = s
		}
	}
	require.NotNil(t, client, "expected an otelhttp client span for the IdP round-trip")
	assert.Equal(t, "HTTP POST", client.Name())
	assert.Equal(t, parent.SpanContext().SpanID(), client.Parent().SpanID(),
		"IdP client span must nest under the request's active span")

	// No token / credential value belongs on the client span attributes.
	for _, kv := range client.Attributes() {
		key := strings.ToLower(string(kv.Key))
		assert.NotContains(t, key, "token")
		assert.NotContains(t, key, "authorization")
	}
}

// TestNewIdPHTTPClient_TracingDisabled pins that the otelhttp wrap is a safe
// no-op when tracing is disabled (the global provider is the default noop):
// the request still succeeds and nothing is exported.
func TestNewIdPHTTPClient_TracingDisabled(t *testing.T) {
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(noop.NewTracerProvider())
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	var gotResp bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		gotResp = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, nil)
	require.NoError(t, err)

	// With tracing off the otelhttp wrap is a no-op: the IdP call still works.
	resp, err := NewIdPHTTPClient(5 * time.Second).Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, gotResp, "IdP request must reach the server with tracing disabled")
}

// TestNewIdPHTTPClient_EmitsNoHTTPClientMetrics pins that the otelhttp wrap is
// trace-only: with a real global meter provider installed, an IdP round-trip
// must not auto-emit otelhttp's HTTP-client instruments — Tyk owns its own
// metric instrumentation (the tyk.oauth2.exchange.* instruments).
func TestNewIdPHTTPClient_EmitsNoHTTPClientMetrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	t.Cleanup(func() { otel.SetMeterProvider(prev) })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, nil)
	require.NoError(t, err)
	resp, err := NewIdPHTTPClient(5 * time.Second).Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	for _, sm := range rm.ScopeMetrics {
		assert.Empty(t, sm.Metrics, "IdP transport must not emit metrics (scope %s)", sm.Scope.Name)
	}
}
