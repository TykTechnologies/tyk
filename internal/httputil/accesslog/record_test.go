package accesslog_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/httputil/accesslog"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/request"

	"github.com/TykTechnologies/tyk-pump/analytics"
)

func TestRecord(t *testing.T) {
	latency := analytics.Latency{
		Total:    150,
		Upstream: 120,
		Gateway:  30,
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/path?userid=1", nil)
	req.RemoteAddr = "0.0.0.0"
	req.Header.Set("User-Agent", "user-agent")

	resp := &http.Response{
		StatusCode: http.StatusOK,
	}

	record := accesslog.NewRecord()
	record.WithRequest(req, latency)
	record.WithResponse(resp)

	got := record.Fields(nil)

	want := logrus.Fields{
		"prefix":           "access-log",
		"client_ip":        request.RealIP(req),
		"remote_addr":      "0.0.0.0",
		"host":             "example.com",
		"latency_gateway":  int64(30),
		"latency_total":    int64(150),
		"method":           http.MethodGet,
		"path":             "/path",
		"protocol":         "HTTP/1.1",
		"status":           http.StatusOK,
		"upstream_addr":    "http://example.com/path",
		"upstream_latency": int64(120),
		"user_agent":       "user-agent",
	}

	assert.Equal(t, want, got)
}

func TestWithTraceID(t *testing.T) {
	tests := []struct {
		name          string
		setupRequest  func(t *testing.T) *http.Request
		expectTraceID bool
	}{
		{
			name: "no trace context - field not added",
			setupRequest: func(_ *testing.T) *http.Request {
				return httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
			},
			expectTraceID: false,
		},
		{
			name: "valid trace context - field added",
			setupRequest: func(t *testing.T) *http.Request {
				// Create OTel provider with HTTP exporter
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				}))
				t.Cleanup(srv.Close)

				cfg := &otel.OpenTelemetry{
					Enabled:  true,
					Exporter: "http",
					Endpoint: srv.URL,
				}
				provider := otel.InitOpenTelemetry(context.Background(), logrus.New(), cfg, "test", "v1", false, "", false, nil)

				// Create a span with trace context
				_, span := provider.Tracer().Start(context.Background(), "test-span")
				t.Cleanup(func() { span.End() })

				req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
				ctx := otel.ContextWithSpan(req.Context(), span)
				return req.WithContext(ctx)
			},
			expectTraceID: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.setupRequest(t)
			record := accesslog.NewRecord().WithTraceID(req)
			fields := record.Fields(nil)

			_, exists := fields["trace_id"]
			assert.Equal(t, tc.expectTraceID, exists)
		})
	}
}
