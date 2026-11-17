package adapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	sdkjsonrpc "github.com/modelcontextprotocol/go-sdk/jsonrpc"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

const sdkModernProtocolVersion = "2026-07-28"

func TestSDKV17ProtocolContracts(t *testing.T) {
	assert.Equal(t, "io.modelcontextprotocol/protocolVersion", mcpsdk.MetaKeyProtocolVersion)
	assert.Equal(t, "io.modelcontextprotocol/clientCapabilities", mcpsdk.MetaKeyClientCapabilities)
	assert.Equal(t, "io.modelcontextprotocol/clientInfo", mcpsdk.MetaKeyClientInfo)
	assert.Equal(t, "io.modelcontextprotocol/serverInfo", mcpsdk.MetaKeyServerInfo)
	assert.EqualValues(t, -32020, mcpsdk.CodeHeaderMismatch)
	assert.EqualValues(t, sdkjsonrpc.CodeInvalidParams, mcpsdk.CodeResourceNotFound)

	err := mcpsdk.ResourceNotFoundError("file:///missing.txt")
	var rpcErr *sdkjsonrpc.Error
	require.ErrorAs(t, err, &rpcErr)
	assert.EqualValues(t, sdkjsonrpc.CodeInvalidParams, rpcErr.Code)
}

func TestSDKV17ModernDiscoveryCanaryWithoutProductionStatelessRouting(t *testing.T) {
	adapter := newSDKV17TestAdapter(t)

	t.Run("stateless transport advertises modern discovery metadata and cache fields", func(t *testing.T) {
		handler := adapter.StreamableHTTPHandler(&mcpsdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
		response := serveSDKV17Discovery(t, handler, sdkModernProtocolVersion, sdkModernProtocolVersion)
		assert.Equal(t, http.StatusOK, response.Code, response.Body.String())
		assert.Empty(t, response.Header().Get("Mcp-Session-Id"))

		result := sdkV17Result(t, response)
		assert.Equal(t, "complete", result["resultType"])
		assert.Equal(t, "public", result["cacheScope"])
		assert.EqualValues(t, 0, result["ttlMs"])
		supported := stringSlice(t, result["supportedVersions"])
		assert.Contains(t, supported, sdkModernProtocolVersion)
		meta := result["_meta"].(map[string]any)
		serverInfo := meta[mcpsdk.MetaKeyServerInfo].(map[string]any)
		assert.Equal(t, "Orders [MCP adapter]", serverInfo["name"])
	})

	t.Run("mismatched modern declaration uses header mismatch code", func(t *testing.T) {
		handler := adapter.StreamableHTTPHandler(&mcpsdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
		response := serveSDKV17Discovery(t, handler, "2025-11-25", sdkModernProtocolVersion)
		assert.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
		var envelope map[string]any
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &envelope))
		errObject := envelope["error"].(map[string]any)
		assert.EqualValues(t, mcpsdk.CodeHeaderMismatch, errObject["code"])
	})

	t.Run("adapter-owned production handler remains stateful", func(t *testing.T) {
		first := adapter.StreamableHTTPHandler(nil)
		second := adapter.StreamableHTTPHandler(nil)
		assert.Equal(t, first, second, "nil options must reuse the cached stateful handler")

		response := serveSDKV17Discovery(t, first, sdkModernProtocolVersion, sdkModernProtocolVersion)
		assert.Equal(t, http.StatusOK, response.Code, response.Body.String())
		supported := stringSlice(t, sdkV17Result(t, response)["supportedVersions"])
		assert.False(t, slices.Contains(supported, sdkModernProtocolVersion),
			"TT-18014 must not enable modern stateless production routing")
		assert.NotEmpty(t, supported)
	})
}

func TestSDKV17LegacySessionCompatibilityCanary(t *testing.T) {
	adapter := newSDKV17TestAdapter(t)
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "v1.7-canary", Version: "1"}, nil)
	session, err := client.Connect(context.Background(), &mcpsdk.StreamableClientTransport{
		Endpoint:   "http://mcp.test/mcp",
		HTTPClient: &http.Client{Transport: loopbackRoundTripper{handler: adapter.StreamableHTTPHandler(nil)}},
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, session.Close()) })

	initialize := session.InitializeResult()
	require.NotNil(t, initialize)
	assert.NotEqual(t, sdkModernProtocolVersion, initialize.ProtocolVersion)
	list, err := session.ListTools(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, list.Tools, 2)
	assert.Equal(t, "public", list.GetCacheScope())
	assert.Zero(t, list.GetTTLMs())
}

func newSDKV17TestAdapter(t *testing.T) *SDKAdapter {
	t.Helper()
	adapter, err := NewSDKAdapter(SDKServerConfig{
		Name:  "Orders [MCP adapter]",
		Tools: sampleTools(),
		CallTool: func(context.Context, *oas.DerivedTool, map[string]any) (*Recorder, error) {
			return NewRecorder(), nil
		},
	})
	require.NoError(t, err)
	return adapter
}

func serveSDKV17Discovery(t *testing.T, handler http.Handler, headerVersion, bodyVersion string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{` +
		`"io.modelcontextprotocol/protocolVersion":"` + bodyVersion + `",` +
		`"io.modelcontextprotocol/clientCapabilities":{},` +
		`"io.modelcontextprotocol/clientInfo":{"name":"canary","version":"1"}}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", headerVersion)
	req.Header.Set("Mcp-Method", "server/discover")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func sdkV17Result(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &envelope))
	result, ok := envelope["result"].(map[string]any)
	require.True(t, ok, "response has no result: %s", response.Body.String())
	return result
}

func stringSlice(t *testing.T, value any) []string {
	t.Helper()
	values, ok := value.([]any)
	require.True(t, ok)
	result := make([]string, 0, len(values))
	for _, value := range values {
		item, ok := value.(string)
		require.True(t, ok)
		result = append(result, item)
	}
	return result
}
