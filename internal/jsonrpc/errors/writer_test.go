package errors

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/mcp"
)

func TestWriteJSONRPCError(t *testing.T) {
	tests := []struct {
		name               string
		requestID          interface{}
		httpCode           int
		message            string
		expectedRPCCode    int
		expectedHTTPStatus int
	}{
		{
			name:               "auth failure with string ID",
			requestID:          "req-123",
			httpCode:           http.StatusUnauthorized,
			message:            "Authentication required",
			expectedRPCCode:    CodeAuthRequired,
			expectedHTTPStatus: http.StatusUnauthorized,
		},
		{
			name:               "rate limit with numeric ID",
			requestID:          float64(42), // JSON unmarshals numbers as float64
			httpCode:           http.StatusTooManyRequests,
			message:            "Rate limit exceeded",
			expectedRPCCode:    CodeRateLimitExceeded,
			expectedHTTPStatus: http.StatusTooManyRequests,
		},
		{
			name:               "access denied with null ID",
			requestID:          nil,
			httpCode:           http.StatusForbidden,
			message:            "Access denied",
			expectedRPCCode:    CodeAccessDenied,
			expectedHTTPStatus: http.StatusForbidden,
		},
		{
			name:               "internal error",
			requestID:          "xyz",
			httpCode:           http.StatusInternalServerError,
			message:            "Internal server error",
			expectedRPCCode:    mcp.JSONRPCInternalError,
			expectedHTTPStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			WriteJSONRPCError(w, tt.requestID, tt.httpCode, tt.message)

			// Check HTTP status
			assert.Equal(t, tt.expectedHTTPStatus, w.Code)

			// Check content type
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

			// Parse response body
			var response JSONRPCErrorResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			// Verify JSON-RPC structure
			assert.Equal(t, apidef.JsonRPC20, response.JSONRPC)
			assert.Equal(t, tt.expectedRPCCode, response.Error.Code)
			assert.Equal(t, tt.message, response.Error.Message)
			assert.Equal(t, tt.requestID, response.ID)

			// Verify data field contains HTTP code
			if response.Error.Data != nil {
				dataMap, ok := response.Error.Data.(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, float64(tt.httpCode), dataMap["http_code"])
			}
		})
	}
}

func TestWriteJSONRPCError_ValidJSONOutput(t *testing.T) {
	w := httptest.NewRecorder()
	requestID := "test-123"
	message := "Test error message"

	WriteJSONRPCError(w, requestID, http.StatusForbidden, message)

	// Verify output is valid JSON
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Verify required JSON-RPC fields
	assert.Equal(t, "2.0", response["jsonrpc"])
	assert.NotNil(t, response["error"])
	assert.Equal(t, requestID, response["id"])

	// Verify error structure
	errorObj, ok := response["error"].(map[string]interface{})
	require.True(t, ok)
	assert.NotNil(t, errorObj["code"])
	assert.Equal(t, message, errorObj["message"])
}

func TestWriteJSONRPCError_MessageEscaping(t *testing.T) {
	w := httptest.NewRecorder()
	message := `Message with "quotes" and <html>`

	WriteJSONRPCError(w, "test", http.StatusForbidden, message)

	var response JSONRPCErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Message should be properly escaped in JSON
	assert.Equal(t, message, response.Error.Message)
}

func TestWriteJSONRPCError_DifferentIDTypes(t *testing.T) {
	tests := []struct {
		name      string
		requestID interface{}
	}{
		{"string ID", "abc-123"},
		{"integer ID", float64(123)}, // JSON unmarshals numbers as float64
		{"null ID", nil},
		{"float ID", 123.456},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			WriteJSONRPCError(w, tt.requestID, http.StatusBadRequest, "test")

			var response JSONRPCErrorResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			assert.Equal(t, tt.requestID, response.ID)
		})
	}
}

func TestWriteJSONRPCError_ReturnsResponseBody(t *testing.T) {
	w := httptest.NewRecorder()
	requestID := "test-123"
	message := "Test error"

	body := WriteJSONRPCError(w, requestID, http.StatusForbidden, message)

	// Verify returned body matches what was written
	assert.Equal(t, w.Body.Bytes(), body)

	// Verify body is valid JSON-RPC response
	var response JSONRPCErrorResponse
	err := json.Unmarshal(body, &response)
	require.NoError(t, err)

	assert.Equal(t, apidef.JsonRPC20, response.JSONRPC)
	assert.Equal(t, message, response.Error.Message)
	assert.Equal(t, requestID, response.ID)
}
