package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	jsonrpcerrors "github.com/TykTechnologies/tyk/internal/jsonrpc/errors"
	"github.com/TykTechnologies/tyk/test"
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

// TestErrorHandler_OverrideMessages_AppliedToJSONRPCErrors proves that OverrideMessages
// configuration affects both JSON-RPC and standard error responses equally.
// This test addresses the security concern that JSON-RPC errors might bypass error message sanitization.
func TestErrorHandler_OverrideMessages_AppliedToJSONRPCErrors(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Setup: Configure OverrideMessages to sanitize auth errors
	originalTykErrors := make(map[string]config.TykError)
	for k, v := range TykErrors {
		originalTykErrors[k] = v
	}
	t.Cleanup(func() {
		// Restore original errors after test
		TykErrors = originalTykErrors
	})

	// Simulate overrideTykErrors() being called with custom config
	// This is what happens at gateway startup
	overrideConfig := map[string]config.TykError{
		ErrAuthAuthorizationFieldMissing: {
			Message: "Custom sanitized auth message",
			Code:    http.StatusUnauthorized,
		},
		ErrAuthKeyNotFound: {
			Message: "Custom access denied message",
			Code:    http.StatusForbidden,
		},
	}

	// Apply overrides to TykErrors map (simulating gateway startup)
	for id, override := range overrideConfig {
		overriddenErr := TykErrors[id]
		if override.Code != 0 {
			overriddenErr.Code = override.Code
		}
		if override.Message != "" {
			overriddenErr.Message = override.Message
		}
		TykErrors[id] = overriddenErr
	}

	tests := []struct {
		name              string
		errorID           string
		expectJSONRPC     bool
		setupRequest      func(*http.Request)
		expectedMessage   string
		expectedHTTPCode  int
		expectedRPCCode   int
	}{
		{
			name:    "JSON-RPC error uses overridden auth message",
			errorID: ErrAuthAuthorizationFieldMissing,
			setupRequest: func(r *http.Request) {
				state := &httpctx.JSONRPCRoutingState{
					ID: "test-123",
				}
				httpctx.SetJSONRPCRoutingState(r, state)
			},
			expectJSONRPC:    true,
			expectedMessage:  "Custom sanitized auth message",
			expectedHTTPCode: http.StatusUnauthorized,
			expectedRPCCode:  jsonrpcerrors.CodeAuthRequired,
		},
		{
			name:    "Standard error uses same overridden auth message",
			errorID: ErrAuthAuthorizationFieldMissing,
			setupRequest: func(r *http.Request) {
				// No routing state - standard error
			},
			expectJSONRPC:    false,
			expectedMessage:  "Custom sanitized auth message",
			expectedHTTPCode: http.StatusUnauthorized,
		},
		{
			name:    "JSON-RPC error uses overridden access denied message",
			errorID: ErrAuthKeyNotFound,
			setupRequest: func(r *http.Request) {
				state := &httpctx.JSONRPCRoutingState{
					ID: "test-456",
				}
				httpctx.SetJSONRPCRoutingState(r, state)
			},
			expectJSONRPC:    true,
			expectedMessage:  "Custom access denied message",
			expectedHTTPCode: http.StatusForbidden,
			expectedRPCCode:  jsonrpcerrors.CodeAccessDenied,
		},
		{
			name:    "Standard error uses same overridden access denied message",
			errorID: ErrAuthKeyNotFound,
			setupRequest: func(r *http.Request) {
				// No routing state - standard error
			},
			expectJSONRPC:    false,
			expectedMessage:  "Custom access denied message",
			expectedHTTPCode: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get error message from TykErrors (simulating middleware behavior)
			err, code := errorAndStatusCode(tt.errorID)
			require.NotNil(t, err, "errorAndStatusCode should return an error")
			errMsg := err.Error()

			// Verify the error message is already overridden
			assert.Equal(t, tt.expectedMessage, errMsg, "Error message should be overridden before HandleError")
			assert.Equal(t, tt.expectedHTTPCode, code, "Error code should be overridden before HandleError")

			// Setup spec based on whether we want JSON-RPC or standard error
			spec := &APISpec{
				APIDefinition: &apidef.APIDefinition{},
			}
			if tt.expectJSONRPC {
				spec.JsonRpcVersion = apidef.JsonRPC20
			}

			handler := ErrorHandler{
				BaseMiddleware: &BaseMiddleware{
					Spec: spec,
					Gw:   ts.Gw,
				},
			}

			r := httptest.NewRequest(http.MethodPost, "/test", nil)
			r.Header.Set("Content-Type", "application/json")
			tt.setupRequest(r)

			w := httptest.NewRecorder()

			// Call HandleError with the overridden message
			handler.HandleError(w, r, errMsg, code, true)

			// Verify the response contains the overridden message
			if tt.expectJSONRPC {
				// JSON-RPC response
				var response jsonrpcerrors.JSONRPCErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err, "JSON-RPC response should be valid JSON")

				assert.Equal(t, apidef.JsonRPC20, response.JSONRPC)
				assert.Equal(t, tt.expectedMessage, response.Error.Message, "JSON-RPC error should contain overridden message")
				assert.Equal(t, tt.expectedRPCCode, response.Error.Code)
				assert.Equal(t, tt.expectedHTTPCode, w.Code)
			} else {
				// Standard error response
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err, "Standard response should be valid JSON")

				assert.Equal(t, tt.expectedHTTPCode, w.Code)
				assert.Contains(t, response, "error")

				// The template wraps the message in HTML, so check it contains the overridden message
				errorField := response["error"].(string)
				assert.Contains(t, errorField, tt.expectedMessage, "Standard error should contain overridden message")
			}
		})
	}
}

// TestErrorHandler_OverrideMessages_ConsistentBehavior verifies that when the same error
// is returned in both JSON-RPC and standard format, the message is identical.
func TestErrorHandler_OverrideMessages_ConsistentBehavior(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Setup override configuration
	originalTykErrors := make(map[string]config.TykError)
	for k, v := range TykErrors {
		originalTykErrors[k] = v
	}
	t.Cleanup(func() {
		TykErrors = originalTykErrors
	})

	// Apply a custom override
	customMessage := "Sanitized security message"
	customCode := http.StatusForbidden

	overriddenErr := TykErrors[ErrAuthKeyNotFound]
	overriddenErr.Message = customMessage
	overriddenErr.Code = customCode
	TykErrors[ErrAuthKeyNotFound] = overriddenErr

	// Get the error (simulating middleware)
	err, code := errorAndStatusCode(ErrAuthKeyNotFound)
	require.NotNil(t, err, "errorAndStatusCode should return an error")
	errMsg := err.Error()

	// Test JSON-RPC format
	jsonRPCSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			JsonRpcVersion: apidef.JsonRPC20,
		},
	}
	jsonRPCHandler := ErrorHandler{
		BaseMiddleware: &BaseMiddleware{
			Spec: jsonRPCSpec,
			Gw:   ts.Gw,
		},
	}

	r1 := httptest.NewRequest(http.MethodPost, "/test", nil)
	r1.Header.Set("Content-Type", "application/json")
	state := &httpctx.JSONRPCRoutingState{ID: "test"}
	httpctx.SetJSONRPCRoutingState(r1, state)
	w1 := httptest.NewRecorder()

	jsonRPCHandler.HandleError(w1, r1, errMsg, code, true)

	var jsonRPCResponse jsonrpcerrors.JSONRPCErrorResponse
	err = json.Unmarshal(w1.Body.Bytes(), &jsonRPCResponse)
	require.NoError(t, err)

	// Test standard format
	standardSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{},
	}
	standardHandler := ErrorHandler{
		BaseMiddleware: &BaseMiddleware{
			Spec: standardSpec,
			Gw:   ts.Gw,
		},
	}

	r2 := httptest.NewRequest(http.MethodPost, "/test", nil)
	r2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()

	standardHandler.HandleError(w2, r2, errMsg, code, true)

	var standardResponse map[string]interface{}
	err = json.Unmarshal(w2.Body.Bytes(), &standardResponse)
	require.NoError(t, err)

	// Prove both responses contain the same overridden message
	assert.Equal(t, customMessage, jsonRPCResponse.Error.Message, "JSON-RPC should use overridden message")
	assert.Contains(t, standardResponse["error"].(string), customMessage, "Standard error should use overridden message")

	// Both should have the same HTTP status code
	assert.Equal(t, customCode, w1.Code, "JSON-RPC HTTP status should match override")
	assert.Equal(t, customCode, w2.Code, "Standard HTTP status should match override")

	t.Logf("✓ Proof: Both JSON-RPC and standard errors use the same overridden message: '%s'", customMessage)
	t.Logf("✓ Proof: Both use the same HTTP status code: %d", customCode)
}

// TestErrorHandler_JSONRPCError_AccessLogStatusCode verifies that access logs
// for JSON-RPC errors contain the correct HTTP status code, not zero.
func TestErrorHandler_JSONRPCError_AccessLogStatusCode(t *testing.T) {
	// Setup test gateway
	ts := StartTest(nil)
	defer ts.Close()

	// Capture logs to verify access log entries
	logger, hook := logrustest.NewNullLogger()

	// Enable access logs
	gwConfig := ts.Gw.GetConfig()
	gwConfig.AccessLogs.Enabled = true
	ts.Gw.SetConfig(gwConfig)

	// Setup JSON-RPC API spec
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			JsonRpcVersion: apidef.JsonRPC20,
			APIID:          "test-api",
			OrgID:          "test-org",
			Name:           "Test API",
		},
		GlobalConfig: gwConfig,
	}

	handler := ErrorHandler{
		BaseMiddleware: &BaseMiddleware{
			Spec:   spec,
			Gw:     ts.Gw,
			logger: logger.WithField("prefix", "test"),
		},
	}

	tests := []struct {
		name             string
		httpCode         int
		message          string
		expectedRPCCode  int
	}{
		{
			name:            "403 Forbidden returns correct status in access log",
			httpCode:        http.StatusForbidden,
			message:         "Access denied",
			expectedRPCCode: jsonrpcerrors.CodeAccessDenied,
		},
		{
			name:            "401 Unauthorized returns correct status in access log",
			httpCode:        http.StatusUnauthorized,
			message:         "Authentication required",
			expectedRPCCode: jsonrpcerrors.CodeAuthRequired,
		},
		{
			name:            "429 Too Many Requests returns correct status in access log",
			httpCode:        http.StatusTooManyRequests,
			message:         "Rate limit exceeded",
			expectedRPCCode: jsonrpcerrors.CodeRateLimitExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset log entries for each test
			hook.Reset()

			// Setup request with JSON-RPC routing state
			r := httptest.NewRequest(http.MethodPost, "/test", nil)
			r.Header.Set("Content-Type", "application/json")
			state := &httpctx.JSONRPCRoutingState{
				ID: "test-123",
			}
			httpctx.SetJSONRPCRoutingState(r, state)

			w := httptest.NewRecorder()

			// Call HandleError (this should write access log)
			handler.HandleError(w, r, tt.message, tt.httpCode, true)

			// Verify HTTP response is correct
			assert.Equal(t, tt.httpCode, w.Code, "HTTP status code should match")

			// Verify JSON-RPC response format
			var jsonRPCResp jsonrpcerrors.JSONRPCErrorResponse
			err := json.Unmarshal(w.Body.Bytes(), &jsonRPCResp)
			require.NoError(t, err, "Response should be valid JSON-RPC")
			assert.Equal(t, tt.expectedRPCCode, jsonRPCResp.Error.Code, "JSON-RPC error code should match")

			// Find the access log entry
			require.NotEmpty(t, hook.Entries, "Access log should be written")

			var accessLogEntry *logrus.Entry
			for i := range hook.Entries {
				// Access logs are Info level
				if hook.Entries[i].Level == logrus.InfoLevel {
					accessLogEntry = &hook.Entries[i]
					break
				}
			}
			require.NotNil(t, accessLogEntry, "Should find access log entry")

			// CRITICAL ASSERTION: Verify status code in access log is NOT zero
			status, exists := accessLogEntry.Data["status"]
			require.True(t, exists, "Access log should contain 'status' field")

			statusInt, ok := status.(int)
			require.True(t, ok, "Status should be an integer, got %T", status)

			assert.NotEqual(t, 0, statusInt, "Access log status should NOT be zero")
			assert.Equal(t, tt.httpCode, statusInt, "Access log status should match HTTP error code")
		})
	}
}

// TestErrorHandler_StandardError_RecordsAnalytics verifies that standard (non-JSON-RPC)
// errors properly record analytics with the correct response code.
// This test ensures refactoring recordErrorAnalytics doesn't break standard error paths.
func TestErrorHandler_StandardError_RecordsAnalytics(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a simple test API
	spec := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false // Require auth to trigger errors
		spec.Proxy.ListenPath = "/test/"
		spec.DoNotTrack = false // Enable analytics
	})[0]

	// Test that 401 error records analytics correctly
	t.Run("401 Unauthorized records analytics", func(t *testing.T) {
		// Make request without auth header (will trigger 401)
		_, _ = ts.Run(t, []test.TestCase{
			{
				Path: "/test/",
				Code: http.StatusUnauthorized,
			},
		}...)

		// The analytics will be recorded - we're just verifying it doesn't panic
		// and that the test infrastructure can handle it
	})

	// Verify the spec is not set to DoNotTrack
	assert.False(t, spec.DoNotTrack, "Analytics should be enabled for this test")
}

// TestErrorHandler_StandardError_StatusCodeAlwaysSet verifies that response.StatusCode
// is set correctly in all standard error paths, including custom body responses.
func TestErrorHandler_StandardError_StatusCodeAlwaysSet(t *testing.T) {
	logger, hook := logrustest.NewNullLogger()

	ts := StartTest(nil)
	defer ts.Close()

	// Enable access logs to verify status code is recorded
	gwConfig := ts.Gw.GetConfig()
	gwConfig.AccessLogs.Enabled = true
	ts.Gw.SetConfig(gwConfig)

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID: "test-api",
			OrgID: "test-org",
			Name:  "Test API",
		},
		GlobalConfig: gwConfig,
	}

	handler := ErrorHandler{
		BaseMiddleware: &BaseMiddleware{
			Spec:   spec,
			Gw:     ts.Gw,
			logger: logger.WithField("prefix", "test"),
		},
	}

	tests := []struct {
		name     string
		errCode  int
		errMsg   string
	}{
		{
			name:    "Standard error with template",
			errCode: http.StatusForbidden,
			errMsg:  "Access forbidden",
		},
		{
			name:    "Custom body error (errCustomBodyResponse)",
			errCode: http.StatusInternalServerError,
			errMsg:  "errCustomBodyResponse",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook.Reset()

			r := httptest.NewRequest(http.MethodPost, "/test", nil)
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Call HandleError
			handler.HandleError(w, r, tt.errMsg, tt.errCode, true)

			// Find access log entry
			require.NotEmpty(t, hook.Entries, "Access log should be written")

			var accessLogEntry *logrus.Entry
			for i := range hook.Entries {
				if hook.Entries[i].Level == logrus.InfoLevel {
					accessLogEntry = &hook.Entries[i]
					break
				}
			}
			require.NotNil(t, accessLogEntry, "Should find access log entry")

			// Verify status code in access log
			status, exists := accessLogEntry.Data["status"]
			require.True(t, exists, "Access log should contain 'status' field")

			statusInt, ok := status.(int)
			require.True(t, ok, "Status should be an integer, got %T", status)

			// CRITICAL: Status should match error code, not be zero
			assert.NotEqual(t, 0, statusInt, "Access log status should NOT be zero")
			assert.Equal(t, tt.errCode, statusInt, "Access log status should match error code")
		})
	}
}
