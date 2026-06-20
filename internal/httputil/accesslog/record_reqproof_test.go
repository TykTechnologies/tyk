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
	tykctx "github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/crypto"
	tykerrors "github.com/TykTechnologies/tyk/internal/errors"
	"github.com/TykTechnologies/tyk/internal/httputil/accesslog"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/request"
)

// Verifies: SYS-REQ-082, SW-REQ-049
// SW-REQ-049:nominal:nominal
// SW-REQ-049:boundary:nominal
// SW-REQ-049:boundary:boundary
// SW-REQ-049:encoding_safety:nominal
// SW-REQ-049:determinism:nominal
func TestRecordFieldsAssembleConfiguredAccessLogMetadata(t *testing.T) {
	t.Run("request response identity and token metadata", func(t *testing.T) {
		latency := analytics.Latency{
			Total:    150,
			Upstream: 120,
			Gateway:  30,
		}
		req := requestWithAccessLogContext(
			httptest.NewRequest(http.MethodPost, "https://api.example.test/v1/tools?debug=true", nil),
			"secret-token",
			"",
			"",
			"",
			0,
		)
		req.RemoteAddr = "203.0.113.10:12345"
		req.Header.Set("User-Agent", "reqproof-agent")
		resp := &http.Response{StatusCode: http.StatusAccepted}

		record := accesslog.NewRecord().
			WithApiKey(req, false, func(token string) string { return "masked:" + token }).
			WithRequest(req, latency).
			WithResponse(resp).
			WithAPIID("api-1", "Weather API", "org-1").
			WithAPIType("mcp")

		fields := record.Fields(nil)
		expected := logrus.Fields{
			"prefix":           "access-log",
			"api_key":          "masked:secret-token",
			"api_id":           "api-1",
			"api_name":         "Weather API",
			"api_type":         "mcp",
			"org_id":           "org-1",
			"client_ip":        request.RealIP(req),
			"host":             "api.example.test",
			"latency_gateway":  int64(30),
			"latency_total":    int64(150),
			"method":           http.MethodPost,
			"path":             "/v1/tools",
			"protocol":         "HTTP/1.1",
			"remote_addr":      "203.0.113.10:12345",
			"status":           http.StatusAccepted,
			"upstream_addr":    "https://api.example.test/v1/tools",
			"upstream_latency": int64(120),
			"user_agent":       "reqproof-agent",
		}
		assert.Equal(t, expected, fields)

		filteredA := record.Fields([]string{"api_key", "method", "status"})
		filteredB := record.Fields([]string{"api_key", "method", "status"})
		assert.Equal(t, logrus.Fields{
			"prefix":  "access-log",
			"api_key": "masked:secret-token",
			"method":  http.MethodPost,
			"status":  http.StatusAccepted,
		}, filteredA)
		assert.Equal(t, filteredA, filteredB)

		hashed := accesslog.NewRecord().
			WithApiKey(req, true, func(string) string {
				t.Fatal("obfuscator must not be used when hashKeys is enabled")
				return ""
			}).
			Fields(nil)
		assert.Equal(t, crypto.HashKey("secret-token", true), hashed["api_key"])
	})

	t.Run("unavailable optional metadata is omitted before filtering", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://api.example.test/health", nil)

		fields := accesslog.NewRecord().
			WithTraceID(req).
			WithAPIID("", "", "org-only").
			WithErrorClassification(nil).
			WithMCP(req).
			Fields([]string{"api_id", "org_id", "trace_id", "mcp_method"})

		assert.Equal(t, logrus.Fields{
			"prefix": "access-log",
			"org_id": "org-only",
		}, fields)
	})

	t.Run("trace error classification and MCP metadata are preserved when available", func(t *testing.T) {
		req, expectedTraceID := tracedAccessLogRequest(t)
		req = requestWithAccessLogContext(req, "", "tools/call", "tool", "get_weather", -32601)

		classification := tykerrors.NewErrorClassification(tykerrors.UCF, "connection_refused").
			WithSource("ReverseProxy").
			WithTarget("api.backend.test:443").
			WithUpstreamStatus(http.StatusBadGateway).
			WithTLSInfo(time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC), "CN=api.backend.test").
			WithCircuitBreakerState("OPEN")

		fields := accesslog.NewRecord().
			WithTraceID(req).
			WithErrorClassification(classification).
			WithMCP(req).
			Fields(nil)

		assert.Equal(t, expectedTraceID, fields["trace_id"])
		assert.Equal(t, "UCF", fields["response_flag"])
		assert.Equal(t, "connection_refused", fields["response_code_details"])
		assert.Equal(t, "ReverseProxy", fields["error_source"])
		assert.Equal(t, "api.backend.test:443", fields["error_target"])
		assert.Equal(t, http.StatusBadGateway, fields["upstream_status"])
		assert.Equal(t, "2026-06-20T12:00:00Z", fields["tls_cert_expiry"])
		assert.Equal(t, "CN=api.backend.test", fields["tls_cert_subject"])
		assert.Equal(t, "OPEN", fields["circuit_breaker_state"])
		assert.Equal(t, "tools/call", fields["mcp_method"])
		assert.Equal(t, "tool", fields["mcp_primitive_type"])
		assert.Equal(t, "get_weather", fields["mcp_primitive_name"])
		assert.Equal(t, -32601, fields["mcp_error_code"])
	})
}

func requestWithAccessLogContext(req *http.Request, token, mcpMethod, primitiveType, primitiveName string, errorCode int) *http.Request {
	reqCtx := req.Context()
	if token != "" {
		reqCtx = context.WithValue(reqCtx, tykctx.AuthToken, token)
	}
	if mcpMethod != "" {
		reqCtx = context.WithValue(reqCtx, tykctx.MCPMethod, mcpMethod)
	}
	if primitiveType != "" {
		reqCtx = context.WithValue(reqCtx, tykctx.MCPPrimitiveType, primitiveType)
	}
	if primitiveName != "" {
		reqCtx = context.WithValue(reqCtx, tykctx.MCPPrimitiveName, primitiveName)
	}
	if errorCode != 0 {
		reqCtx = context.WithValue(reqCtx, tykctx.JSONRPCErrorCode, errorCode)
	}
	return req.WithContext(reqCtx)
}

func tracedAccessLogRequest(t *testing.T) (*http.Request, string) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	cfg := &otel.OpenTelemetry{BaseOpenTelemetry: otel.BaseOpenTelemetry{
		Enabled: true,
		ExporterConfig: otel.ExporterConfig{
			Exporter: "http",
			Endpoint: srv.URL,
		},
	}}
	provider := otel.InitOpenTelemetry(context.Background(), logrus.New(), cfg, "gateway-id", "v1", false, "", false, nil)
	ctx, span := provider.Tracer().Start(context.Background(), "access-log-record")
	t.Cleanup(func() { span.End() })

	req := httptest.NewRequest(http.MethodPost, "https://api.example.test/mcp", nil)
	req = req.WithContext(otel.ContextWithSpan(req.Context(), span))

	return req, otel.ExtractTraceID(ctx)
}
