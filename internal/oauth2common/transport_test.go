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
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// TestNewIdPHTTPClient_EmitsChildClientSpan pins TC11: when the request context
// carries an active span, the IdP round-trip is emitted as a child client span
// (named for the IdP call) nested under the parent. otelhttp builds the span
// from the propagated context — no manual span code in the exchange path.
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
	assert.Equal(t, "oauth2.idp POST", client.Name())
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
