package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	jsonrpcerrors "github.com/TykTechnologies/tyk/internal/jsonrpc/errors"
)

func TestErrorHandler_HandleError_JSONRPCFormat(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			JsonRpcVersion: apidef.JsonRPC20,
		},
	}

	handler := ErrorHandler{
		BaseMiddleware: &BaseMiddleware{
			Spec: spec,
			Gw:   ts.Gw,
		},
	}

	tests := []struct {
		name               string
		setupRequest       func(*http.Request)
		httpCode           int
		message            string
		expectJSONRPC      bool
		expectedRPCCode    int
		expectedHTTPStatus int
	}{
		{
			name: "returns JSON-RPC error when routing state exists",
			setupRequest: func(r *http.Request) {
				state := &httpctx.JSONRPCRoutingState{
					ID: "test-123",
				}
				httpctx.SetJSONRPCRoutingState(r, state)
			},
			httpCode:           http.StatusForbidden,
			message:            "Access denied",
			expectJSONRPC:      true,
			expectedRPCCode:    jsonrpcerrors.CodeAccessDenied,
			expectedHTTPStatus: http.StatusForbidden,
		},
		{
			name: "returns JSON-RPC error for rate limit",
			setupRequest: func(r *http.Request) {
				state := &httpctx.JSONRPCRoutingState{
					ID: float64(456),
				}
				httpctx.SetJSONRPCRoutingState(r, state)
			},
			httpCode:           http.StatusTooManyRequests,
			message:            "Rate limit exceeded",
			expectJSONRPC:      true,
			expectedRPCCode:    jsonrpcerrors.CodeRateLimitExceeded,
			expectedHTTPStatus: http.StatusTooManyRequests,
		},
		{
			name: "returns standard error when no routing state",
			setupRequest: func(r *http.Request) {
				// No routing state set
			},
			httpCode:      http.StatusForbidden,
			message:       "Access denied",
			expectJSONRPC: false,
		},
		{
			name: "returns standard error when not JSON-RPC 2.0 API",
			setupRequest: func(r *http.Request) {
				state := &httpctx.JSONRPCRoutingState{
					ID: "test-123",
				}
				httpctx.SetJSONRPCRoutingState(r, state)
				// Modify spec to not be JSON-RPC 2.0
				handler.Spec.JsonRpcVersion = ""
			},
			httpCode:      http.StatusForbidden,
			message:       "Access denied",
			expectJSONRPC: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset spec for each test
			handler.Spec.JsonRpcVersion = apidef.JsonRPC20

			r := httptest.NewRequest(http.MethodPost, "/test", nil)
			r.Header.Set("Content-Type", "application/json")
			tt.setupRequest(r)

			w := httptest.NewRecorder()

			handler.HandleError(w, r, tt.message, tt.httpCode, true)

			if tt.expectJSONRPC {
				// Verify JSON-RPC formatted response
				assert.Equal(t, tt.expectedHTTPStatus, w.Code)
				assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

				var response jsonrpcerrors.JSONRPCErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)

				assert.Equal(t, apidef.JsonRPC20, response.JSONRPC)
				assert.Equal(t, tt.expectedRPCCode, response.Error.Code)
				assert.Equal(t, tt.message, response.Error.Message)

				// Verify request ID is preserved
				state := httpctx.GetJSONRPCRoutingState(r)
				assert.Equal(t, state.ID, response.ID)
			} else {
				// Verify standard template-based response
				assert.Equal(t, tt.httpCode, w.Code)
				// Standard response uses template, so check it's not JSON-RPC format
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)

				// Standard error should not have jsonrpc field
				assert.NotContains(t, response, "jsonrpc")
				// Standard error has "error" field with message
				assert.Contains(t, response, "error")
			}
		})
	}
}

func TestErrorHandler_writeJSONRPCError_ReturnsFullResponse(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			JsonRpcVersion: apidef.JsonRPC20,
		},
	}

	handler := ErrorHandler{
		BaseMiddleware: &BaseMiddleware{
			Spec: spec,
			Gw:   ts.Gw,
		},
	}

	r := httptest.NewRequest(http.MethodPost, "/test", nil)
	state := &httpctx.JSONRPCRoutingState{
		ID: "test-123",
	}
	httpctx.SetJSONRPCRoutingState(r, state)

	w := httptest.NewRecorder()

	// Call writeJSONRPCError and capture returned body
	body := handler.writeJSONRPCError(w, r, "Access denied", http.StatusForbidden)

	// Verify returned body is valid JSON-RPC response
	var response jsonrpcerrors.JSONRPCErrorResponse
	err := json.Unmarshal(body, &response)
	require.NoError(t, err)

	assert.Equal(t, apidef.JsonRPC20, response.JSONRPC)
	assert.Equal(t, jsonrpcerrors.CodeAccessDenied, response.Error.Code)
	assert.Equal(t, "Access denied", response.Error.Message)
	assert.Equal(t, "test-123", response.ID)

	// Verify what was written to ResponseWriter matches returned body
	assert.Equal(t, body, w.Body.Bytes())
}

func TestErrorHandler_shouldWriteJSONRPCError(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	tests := []struct {
		name            string
		jsonRpcVersion  string
		hasRoutingState bool
		expected        bool
	}{
		{
			name:            "returns true for JSON-RPC 2.0 with routing state",
			jsonRpcVersion:  apidef.JsonRPC20,
			hasRoutingState: true,
			expected:        true,
		},
		{
			name:            "returns false without routing state",
			jsonRpcVersion:  apidef.JsonRPC20,
			hasRoutingState: false,
			expected:        false,
		},
		{
			name:            "returns false when not JSON-RPC 2.0",
			jsonRpcVersion:  "1.0",
			hasRoutingState: true,
			expected:        false,
		},
		{
			name:            "returns false when version is empty",
			jsonRpcVersion:  "",
			hasRoutingState: true,
			expected:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := &APISpec{
				APIDefinition: &apidef.APIDefinition{
					JsonRpcVersion: tt.jsonRpcVersion,
				},
			}

			handler := ErrorHandler{
				BaseMiddleware: &BaseMiddleware{
					Spec: spec,
					Gw:   ts.Gw,
				},
			}

			r := httptest.NewRequest(http.MethodPost, "/test", nil)
			if tt.hasRoutingState {
				state := &httpctx.JSONRPCRoutingState{
					ID: "test",
				}
				httpctx.SetJSONRPCRoutingState(r, state)
			}

			result := handler.shouldWriteJSONRPCError(r)
			assert.Equal(t, tt.expected, result)
		})
	}
}
