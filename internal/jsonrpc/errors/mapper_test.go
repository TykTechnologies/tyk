package errors

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	tykerrors "github.com/TykTechnologies/tyk/internal/errors"
	"github.com/TykTechnologies/tyk/internal/mcp"
)

func TestMapHTTPStatusToJSONRPCCode(t *testing.T) {
	tests := []struct {
		name            string
		httpStatus      int
		expectedRPCCode int
	}{
		{
			name:            "bad request maps to invalid request",
			httpStatus:      http.StatusBadRequest,
			expectedRPCCode: mcp.JSONRPCInvalidRequest,
		},
		{
			name:            "unauthorized maps to auth required",
			httpStatus:      http.StatusUnauthorized,
			expectedRPCCode: CodeAuthRequired,
		},
		{
			name:            "forbidden maps to access denied",
			httpStatus:      http.StatusForbidden,
			expectedRPCCode: CodeAccessDenied,
		},
		{
			name:            "not found maps to method not found",
			httpStatus:      http.StatusNotFound,
			expectedRPCCode: mcp.JSONRPCMethodNotFound,
		},
		{
			name:            "too many requests maps to rate limit",
			httpStatus:      http.StatusTooManyRequests,
			expectedRPCCode: CodeRateLimitExceeded,
		},
		{
			name:            "internal server error maps to internal error",
			httpStatus:      http.StatusInternalServerError,
			expectedRPCCode: mcp.JSONRPCInternalError,
		},
		{
			name:            "bad gateway maps to upstream error",
			httpStatus:      http.StatusBadGateway,
			expectedRPCCode: CodeUpstreamError,
		},
		{
			name:            "service unavailable maps to upstream error",
			httpStatus:      http.StatusServiceUnavailable,
			expectedRPCCode: CodeUpstreamError,
		},
		{
			name:            "gateway timeout maps to upstream error",
			httpStatus:      http.StatusGatewayTimeout,
			expectedRPCCode: CodeUpstreamError,
		},
		{
			name:            "unknown 5xx maps to internal error",
			httpStatus:      599,
			expectedRPCCode: mcp.JSONRPCInternalError,
		},
		{
			name:            "unknown 4xx maps to server error",
			httpStatus:      418, // I'm a teapot
			expectedRPCCode: CodeServerError,
		},
		{
			name:            "success status returns zero",
			httpStatus:      http.StatusOK,
			expectedRPCCode: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MapHTTPStatusToJSONRPCCode(tt.httpStatus)
			assert.Equal(t, tt.expectedRPCCode, result)
		})
	}
}

func TestSelectJSONRPCCode_ProtocolNamespaceAndClassification(t *testing.T) {
	modern := mcp.NewProtocolContext(mcp.ModernProtocolVersion, "", nil, nil)
	legacy := mcp.NewProtocolContext("2025-03-26", "", nil, nil)

	tests := []struct {
		name       string
		status     int
		class      *tykerrors.ErrorClassification
		legacyCode int
		modernCode int
	}{
		{name: "authentication", status: http.StatusForbidden, class: tykerrors.NewErrorClassification(tykerrors.AKI, "invalid_key"), legacyCode: CodeAuthRequired, modernCode: CodeModernAuthRequired},
		{name: "access", status: http.StatusForbidden, class: tykerrors.NewErrorClassification(tykerrors.ACD, "access_denied"), legacyCode: CodeAccessDenied, modernCode: CodeModernAccessDenied},
		{name: "rate limit", status: http.StatusTooManyRequests, class: tykerrors.NewErrorClassification(tykerrors.RLT, "rate_limited"), legacyCode: CodeRateLimitExceeded, modernCode: CodeModernRateLimitExceeded},
		{name: "upstream", status: http.StatusInternalServerError, class: tykerrors.NewErrorClassification(tykerrors.UCF, "connection_failed"), legacyCode: CodeUpstreamError, modernCode: CodeModernUpstreamError},
		{name: "quota", status: http.StatusForbidden, class: tykerrors.NewErrorClassification(tykerrors.QEX, "quota_exceeded"), legacyCode: CodeQuotaExceeded, modernCode: CodeModernQuotaExceeded},
		{name: "IP blocked", status: http.StatusForbidden, class: tykerrors.NewErrorClassification(tykerrors.IPB, "ip_blocked"), legacyCode: CodeIPBlocked, modernCode: CodeModernIPBlocked},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.legacyCode, SelectJSONRPCCode(test.status, test.class, legacy))
			assert.Equal(t, test.modernCode, SelectJSONRPCCode(test.status, test.class, modern))
		})
	}

	t.Run("standard codes do not move namespaces", func(t *testing.T) {
		assert.Equal(t, mcp.JSONRPCInvalidRequest, SelectJSONRPCCode(http.StatusBadRequest, nil, modern))
		assert.Equal(t, mcp.JSONRPCMethodNotFound, SelectJSONRPCCode(http.StatusNotFound, nil, modern))
		assert.Equal(t, mcp.JSONRPCInternalError, SelectJSONRPCCode(http.StatusInternalServerError, nil, modern))
	})

	t.Run("mismatch remains legacy", func(t *testing.T) {
		mismatch := mcp.NewProtocolContext(mcp.ModernProtocolVersion, "", &mcp.RequestEnvelope{
			Params: []byte(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-03-26"}}`),
		}, nil)
		assert.Equal(t, CodeAccessDenied, SelectJSONRPCCode(http.StatusForbidden, nil, mismatch))
	})
}

func TestMapHTTPStatusToJSONRPCCode_AllDefinedCodes(t *testing.T) {
	// Ensure all common HTTP status codes have defined mappings
	commonStatuses := []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusMethodNotAllowed,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	}

	for _, status := range commonStatuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			code := MapHTTPStatusToJSONRPCCode(status)
			// All error statuses should return non-zero RPC codes
			assert.NotEqual(t, 0, code, "HTTP status %d should map to a JSON-RPC error code", status)
			// All should be in valid JSON-RPC error range
			assert.True(t, code <= -32000, "JSON-RPC code should be in error range")
		})
	}
}
