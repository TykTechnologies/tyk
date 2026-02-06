package accesslog_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/errors"
	"github.com/TykTechnologies/tyk/internal/httputil/accesslog"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/request"
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
				spanCtx := otel.ContextWithSpan(req.Context(), span)
				return req.WithContext(spanCtx)
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

func TestWithAPIID(t *testing.T) {
	tests := []struct {
		name           string
		apiID          string
		apiName        string
		orgID          string
		expectedFields logrus.Fields
	}{
		{
			name:    "all fields populated",
			apiID:   "api-123",
			apiName: "Test API",
			orgID:   "org-456",
			expectedFields: logrus.Fields{
				"prefix":   "access-log",
				"api_id":   "api-123",
				"api_name": "Test API",
				"org_id":   "org-456",
			},
		},
		{
			name:    "empty fields omitted",
			apiID:   "api-123",
			apiName: "",
			orgID:   "",
			expectedFields: logrus.Fields{
				"prefix": "access-log",
				"api_id": "api-123",
			},
		},
		{
			name:    "all fields empty",
			apiID:   "",
			apiName: "",
			orgID:   "",
			expectedFields: logrus.Fields{
				"prefix": "access-log",
			},
		},
		{
			name:    "only org_id populated",
			apiID:   "",
			apiName: "",
			orgID:   "org-789",
			expectedFields: logrus.Fields{
				"prefix": "access-log",
				"org_id": "org-789",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			record := accesslog.NewRecord().WithAPIID(tc.apiID, tc.apiName, tc.orgID)
			fields := record.Fields(nil)
			assert.Equal(t, tc.expectedFields, fields)
		})
	}
}

func TestWithAPIID_BuilderChaining(t *testing.T) {
	record := accesslog.NewRecord()
	result := record.WithAPIID("api-123", "Test API", "org-456")

	assert.Same(t, record, result, "WithAPIID should return the same Record for chaining")
}

func TestWithErrorClassification(t *testing.T) {
	tests := []struct {
		name           string
		classification *errors.ErrorClassification
		expectedFields logrus.Fields
	}{
		{
			name:           "nil classification adds no fields",
			classification: nil,
			expectedFields: logrus.Fields{
				"prefix": "access-log",
			},
		},
		{
			name: "basic classification adds core fields",
			classification: errors.NewErrorClassification(errors.UCF, "connection_refused").
				WithSource("ReverseProxy").
				WithTarget("api.backend.com:443"),
			expectedFields: logrus.Fields{
				"prefix":                "access-log",
				"response_flag":         "UCF",
				"response_code_details": "connection_refused",
				"error_source":          "ReverseProxy",
				"error_target":          "api.backend.com:443",
			},
		},
		{
			name: "TLS error includes cert info",
			classification: errors.NewErrorClassification(errors.TLE, "tls_certificate_expired").
				WithSource("ReverseProxy").
				WithTarget("api.backend.com:443").
				WithTLSInfo(time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC), "CN=api.backend.com"),
			expectedFields: logrus.Fields{
				"prefix":                "access-log",
				"response_flag":         "TLE",
				"response_code_details": "tls_certificate_expired",
				"error_source":          "ReverseProxy",
				"error_target":          "api.backend.com:443",
				"tls_cert_expiry":       "2024-01-15T00:00:00Z",
				"tls_cert_subject":      "CN=api.backend.com",
			},
		},
		{
			name: "circuit breaker includes state",
			classification: errors.NewErrorClassification(errors.CBO, "circuit_breaker_open").
				WithSource("ReverseProxy").
				WithTarget("api.backend.com:443").
				WithCircuitBreakerState("OPEN"),
			expectedFields: logrus.Fields{
				"prefix":                "access-log",
				"response_flag":         "CBO",
				"response_code_details": "circuit_breaker_open",
				"error_source":          "ReverseProxy",
				"error_target":          "api.backend.com:443",
				"circuit_breaker_state": "OPEN",
			},
		},
		{
			name: "upstream response includes status",
			classification: errors.NewErrorClassification(errors.URS, "upstream_response_503").
				WithSource("Upstream"). // Upstream responded with error, not a proxy error
				WithTarget("api.backend.com:443").
				WithUpstreamStatus(503),
			expectedFields: logrus.Fields{
				"prefix":                "access-log",
				"response_flag":         "URS",
				"response_code_details": "upstream_response_503",
				"error_source":          "Upstream",
				"error_target":          "api.backend.com:443",
				"upstream_status":       503,
			},
		},
		{
			name: "empty optional fields omitted",
			classification: errors.NewErrorClassification(errors.UCF, "connection_refused").
				WithSource("ReverseProxy").
				WithTarget(""),
			expectedFields: logrus.Fields{
				"prefix":                "access-log",
				"response_flag":         "UCF",
				"response_code_details": "connection_refused",
				"error_source":          "ReverseProxy",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			record := accesslog.NewRecord().WithErrorClassification(tc.classification)
			fields := record.Fields(nil)
			assert.Equal(t, tc.expectedFields, fields)
		})
	}
}

func TestWithErrorClassification_BuilderChaining(t *testing.T) {
	ec := errors.NewErrorClassification(errors.UCF, "connection_refused").
		WithSource("ReverseProxy").
		WithTarget("api.backend.com:443")

	record := accesslog.NewRecord()
	result := record.WithErrorClassification(ec)

	assert.Same(t, record, result, "WithErrorClassification should return the same Record for chaining")
}

func TestWithCacheHit(t *testing.T) {
	tests := []struct {
		name           string
		setupRequest   func(t *testing.T) *http.Request
		expectedFields logrus.Fields
	}{
		{
			name: "cache hit true",
			setupRequest: func(t *testing.T) *http.Request {
				req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
				ctx.WithCacheHit(req, true)
				return req
			},
			expectedFields: logrus.Fields{
				"prefix":    "access-log",
				"cache_hit": true,
			},
		},
		{
			name: "cache hit false",
			setupRequest: func(t *testing.T) *http.Request {
				req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
				ctx.WithCacheHit(req, false)
				return req
			},
			expectedFields: logrus.Fields{
				"prefix":    "access-log",
				"cache_hit": false,
			},
		},
		{
			name: "cache hit not set - field omitted",
			setupRequest: func(t *testing.T) *http.Request {
				return httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
			},
			expectedFields: logrus.Fields{
				"prefix": "access-log",
			},
		},
		{
			name: "cache hit wrong type - field omitted",
			setupRequest: func(t *testing.T) *http.Request {
				req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
				reqCtx := context.WithValue(req.Context(), ctx.CacheHit, "not a bool")
				return req.WithContext(reqCtx)
			},
			expectedFields: logrus.Fields{
				"prefix": "access-log",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.setupRequest(t)
			record := accesslog.NewRecord().WithCacheHit(req)
			fields := record.Fields(nil)
			assert.Equal(t, tc.expectedFields, fields)
		})
	}
}

func TestWithCacheHit_BuilderChaining(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
	ctx.WithCacheHit(req, true)

	record := accesslog.NewRecord()
	result := record.WithCacheHit(req)

	assert.Same(t, record, result, "WithCacheHit should return the same Record for chaining")
}
