package gateway

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/httpctx"
	jsonrpcerrors "github.com/TykTechnologies/tyk/internal/jsonrpc/errors"
	"github.com/TykTechnologies/tyk/internal/mcp"
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

func TestWriteJSONRPCAccessDenied_ModernCodeIsSharedWithContext(t *testing.T) {
	r := httptest.NewRequest("POST", "/mcp", nil)
	envelope := &mcp.RequestEnvelope{JSONRPC: "2.0", Method: "tools/list", ID: 7}
	httpctx.SetMCPProtocolContext(r, mcp.NewProtocolContext(mcp.ModernProtocolVersion, "", envelope, nil))
	httpctx.SetJSONRPCRoutingState(r, &httpctx.JSONRPCRoutingState{Method: envelope.Method, ID: envelope.ID})
	w := httptest.NewRecorder()

	writeJSONRPCAccessDenied(w, r, "denied")

	var response jsonrpcerrors.JSONRPCErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	assert.Equal(t, jsonrpcerrors.CodeModernAccessDenied, response.Error.Code)
	assert.Equal(t, response.Error.Code, ctxGetJSONRPCErrorCode(r))
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

func TestMCPAdapterUsesStatelessHandler(t *testing.T) {
	t.Parallel()
	request := func(header, session, method, params string) *mcp.ProtocolContext {
		return mcp.NewProtocolContext(header, session, &mcp.RequestEnvelope{Method: method, Params: json.RawMessage(params)}, nil)
	}
	modernMetadata := `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}`

	tests := []struct {
		name string
		ctx  *mcp.ProtocolContext
		want bool
	}{
		{"modern", request(mcp.ModernProtocolVersion, "", mcp.MethodToolsList, modernMetadata), true},
		{"modern ignores session header", request(mcp.ModernProtocolVersion, "session", mcp.MethodToolsList, modernMetadata), true},
		{"modern initialize remains stateful", request(mcp.ModernProtocolVersion, "", mcp.MethodInitialize, modernMetadata), false},
		{"explicit legacy", request(mcp.LegacyFallbackProtocolVersion, "", mcp.MethodToolsList, `{}`), false},
		{"session fallback", request("", "session", mcp.MethodToolsList, `{}`), false},
		{"declaration free fallback", request("", "", mcp.MethodToolsList, `{}`), false},
		{"mismatch", request(mcp.ModernProtocolVersion, "", mcp.MethodToolsList, `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}`), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, mcpAdapterUsesStatelessHandler(test.ctx))
		})
	}
}
