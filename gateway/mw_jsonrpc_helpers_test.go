package gateway

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/httpctx"
)

// STK-REQ-067:nominal:nominal
// SYS-REQ-155:nominal:nominal
// SW-REQ-142:nominal:nominal
func TestWriteJSONRPCAccessDenied(t *testing.T) {
	tests := []struct {
		name       string
		state      *httpctx.JSONRPCRoutingState
		detail     string
		expectedID any
	}{
		{
			name: "with routing state",
			state: &httpctx.JSONRPCRoutingState{
				Method: "tools/call",
				ID:     float64(42),
			},
			detail:     "tool 'dangerous_tool' is not available",
			expectedID: float64(42),
		},
		{
			name:       "without routing state",
			detail:     "method 'tools/list' is not available",
			expectedID: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/mcp", nil)
			if tt.state != nil {
				httpctx.SetJSONRPCRoutingState(r, tt.state)
			}

			w := httptest.NewRecorder()
			writeJSONRPCAccessDenied(w, r, tt.detail)

			require.Equal(t, 403, w.Code)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

			var body map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			assert.Equal(t, "2.0", body["jsonrpc"])
			assert.Equal(t, tt.expectedID, body["id"])

			errBody, ok := body["error"].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, float64(-32600), errBody["code"])
			assert.Equal(t, tt.detail, errBody["message"])
		})
	}
}
