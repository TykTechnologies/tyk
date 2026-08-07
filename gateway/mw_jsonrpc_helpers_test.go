package gateway

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/httpctx"
)

func TestWriteJSONRPCAccessDenied_WithState(t *testing.T) {
	r := httptest.NewRequest("POST", "/mcp", nil)
	state := &httpctx.JSONRPCRoutingState{
		Method: "tools/call",
		ID:     42,
	}
	httpctx.SetJSONRPCRoutingState(r, state)

	w := httptest.NewRecorder()
	writeJSONRPCAccessDenied(w, r, "tool 'dangerous_tool' is not available")

	require.Equal(t, 403, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "dangerous_tool")
	assert.Contains(t, body, "jsonrpc")
}

func TestWriteJSONRPCAccessDenied_WithoutState(t *testing.T) {
	r := httptest.NewRequest("POST", "/mcp", nil)
	// No routing state set

	w := httptest.NewRecorder()
	writeJSONRPCAccessDenied(w, r, "method 'tools/list' is not available")

	require.Equal(t, 403, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "jsonrpc")
}
