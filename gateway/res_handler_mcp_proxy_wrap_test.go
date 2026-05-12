package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	mcpproxy "github.com/TykTechnologies/tyk/internal/mcp/proxy"
)

// buildMCPProxyWrapHandler constructs a handler whose Enabled() predicate
// fires (Spec carries the MCPProxy extension on Server).
func buildMCPProxyWrapHandler(t *testing.T) *MCPProxyResponseWrap {
	t.Helper()
	o := oas.OAS{}
	o.SetTykExtension(&oas.XTykAPIGateway{Server: oas.Server{MCPProxy: &oas.MCPProxy{}}})
	return &MCPProxyResponseWrap{
		BaseTykResponseHandler: BaseTykResponseHandler{
			Spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{APIID: "mcp-test", IsOAS: true},
				OAS:           o,
			},
		},
	}
}

// makeToolsCallRequest returns an *http.Request whose context carries the
// JSON-RPC id stash that MCPHandler would have written for a tools/call.
func makeToolsCallRequest(t *testing.T, id any, tool string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req = mcpproxy.SetJSONRPCID(req, id)
	req = mcpproxy.SetToolName(req, tool)
	return req
}

// makeResponse builds a synthetic *http.Response carrying body and headers.
func makeResponse(status int, contentType string, body []byte, extraHeaders map[string]string) *http.Response {
	h := http.Header{}
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	for k, v := range extraHeaders {
		h.Set(k, v)
	}
	return &http.Response{
		StatusCode:    status,
		Status:        http.StatusText(status),
		Header:        h,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

// readEnvelope decodes the wrapped response body into a generic map.
func readEnvelope(t *testing.T, res *http.Response) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func TestMCPProxyResponseWrap_Name(t *testing.T) {
	h := &MCPProxyResponseWrap{}
	assert.Equal(t, "MCPProxyResponseWrap", h.Name())
}

func TestMCPProxyResponseWrap_Success_JSONBody(t *testing.T) {
	h := buildMCPProxyWrapHandler(t)
	req := makeToolsCallRequest(t, float64(7), "getUser")
	body := []byte(`{"name":"alice","age":30}`)
	res := makeResponse(http.StatusOK, "application/json", body, nil)

	require.NoError(t, h.HandleResponse(nil, res, req, nil))

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "application/json", res.Header.Get("Content-Type"))

	env := readEnvelope(t, res)
	assert.Equal(t, "2.0", env["jsonrpc"])
	assert.EqualValues(t, 7, env["id"])

	result := env["result"].(map[string]any)
	assert.Equal(t, false, result["isError"])

	content := result["content"].([]any)
	require.Len(t, content, 1)
	c0 := content[0].(map[string]any)
	assert.Equal(t, "text", c0["type"])
	assert.Equal(t, string(body), c0["text"])

	sc, ok := result["structuredContent"].(map[string]any)
	require.True(t, ok, "structuredContent should be present for JSON body")
	assert.Equal(t, "alice", sc["name"])
	assert.EqualValues(t, 30, sc["age"])
}

func TestMCPProxyResponseWrap_Success_TextBody(t *testing.T) {
	h := buildMCPProxyWrapHandler(t)
	req := makeToolsCallRequest(t, "abc", "echo")
	body := []byte("hello world")
	res := makeResponse(http.StatusOK, "text/plain; charset=utf-8", body, nil)

	require.NoError(t, h.HandleResponse(nil, res, req, nil))

	env := readEnvelope(t, res)
	result := env["result"].(map[string]any)

	_, hasSC := result["structuredContent"]
	assert.False(t, hasSC, "structuredContent must be absent for non-JSON body")

	content := result["content"].([]any)
	c0 := content[0].(map[string]any)
	assert.Equal(t, "hello world", c0["text"])
	assert.Equal(t, false, result["isError"])
}

func TestMCPProxyResponseWrap_Error_401(t *testing.T) {
	h := buildMCPProxyWrapHandler(t)
	req := makeToolsCallRequest(t, float64(1), "tool")
	res := makeResponse(http.StatusUnauthorized, "application/json", []byte(`{"err":"nope"}`), nil)

	require.NoError(t, h.HandleResponse(nil, res, req, nil))

	assert.Equal(t, http.StatusOK, res.StatusCode, "errors must be wrapped as 200 OK")

	env := readEnvelope(t, res)
	result := env["result"].(map[string]any)
	assert.Equal(t, true, result["isError"])

	sc := result["structuredContent"].(map[string]any)
	assert.Equal(t, "auth_revoked", sc["kind"])
	assert.EqualValues(t, 401, sc["upstream_status"])
	assert.Equal(t, `{"err":"nope"}`, sc["body_excerpt"])
}

func TestMCPProxyResponseWrap_Error_429_RetryAfter(t *testing.T) {
	h := buildMCPProxyWrapHandler(t)
	req := makeToolsCallRequest(t, float64(2), "tool")
	res := makeResponse(http.StatusTooManyRequests, "text/plain", []byte("slow down"),
		map[string]string{"Retry-After": "30"})

	require.NoError(t, h.HandleResponse(nil, res, req, nil))

	env := readEnvelope(t, res)
	result := env["result"].(map[string]any)
	sc := result["structuredContent"].(map[string]any)
	assert.Equal(t, "rate_limited", sc["kind"])
	assert.EqualValues(t, 429, sc["upstream_status"])
	assert.EqualValues(t, 30, sc["retry_after_seconds"])
}

func TestMCPProxyResponseWrap_Error_503(t *testing.T) {
	h := buildMCPProxyWrapHandler(t)
	req := makeToolsCallRequest(t, float64(3), "tool")
	res := makeResponse(http.StatusServiceUnavailable, "text/plain", []byte("down"), nil)

	require.NoError(t, h.HandleResponse(nil, res, req, nil))

	env := readEnvelope(t, res)
	result := env["result"].(map[string]any)
	sc := result["structuredContent"].(map[string]any)
	assert.Equal(t, "upstream_5xx", sc["kind"])
	assert.EqualValues(t, 503, sc["upstream_status"])
}

func TestMCPProxyResponseWrap_Error_403(t *testing.T) {
	h := buildMCPProxyWrapHandler(t)
	req := makeToolsCallRequest(t, float64(4), "tool")
	res := makeResponse(http.StatusForbidden, "text/plain", []byte("nope"), nil)

	require.NoError(t, h.HandleResponse(nil, res, req, nil))

	env := readEnvelope(t, res)
	sc := env["result"].(map[string]any)["structuredContent"].(map[string]any)
	assert.Equal(t, "forbidden", sc["kind"])
}

func TestMCPProxyResponseWrap_Error_404(t *testing.T) {
	h := buildMCPProxyWrapHandler(t)
	req := makeToolsCallRequest(t, float64(5), "tool")
	res := makeResponse(http.StatusNotFound, "text/plain", []byte("missing"), nil)

	require.NoError(t, h.HandleResponse(nil, res, req, nil))

	env := readEnvelope(t, res)
	sc := env["result"].(map[string]any)["structuredContent"].(map[string]any)
	assert.Equal(t, "not_found", sc["kind"])
}

func TestMCPProxyResponseWrap_Error_OtherStatus(t *testing.T) {
	h := buildMCPProxyWrapHandler(t)
	req := makeToolsCallRequest(t, float64(6), "tool")
	res := makeResponse(http.StatusBadRequest, "text/plain", []byte("bad"), nil)

	require.NoError(t, h.HandleResponse(nil, res, req, nil))

	env := readEnvelope(t, res)
	sc := env["result"].(map[string]any)["structuredContent"].(map[string]any)
	assert.Equal(t, "upstream_error", sc["kind"])
	assert.EqualValues(t, 400, sc["upstream_status"])
}

func TestMCPProxyResponseWrap_SSE_Bypass(t *testing.T) {
	h := buildMCPProxyWrapHandler(t)
	req := makeToolsCallRequest(t, float64(8), "tool")
	originalBody := []byte("event: foo\ndata: bar\n\n")
	res := makeResponse(http.StatusOK, "text/event-stream", originalBody, nil)
	originalCT := res.Header.Get("Content-Type")
	originalStatus := res.StatusCode

	require.NoError(t, h.HandleResponse(nil, res, req, nil))

	// Body, status, and content-type must be unchanged.
	assert.Equal(t, originalCT, res.Header.Get("Content-Type"))
	assert.Equal(t, originalStatus, res.StatusCode)
	got, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Equal(t, originalBody, got)
}

func TestMCPProxyResponseWrap_NoIDInContext_NoWrap(t *testing.T) {
	h := buildMCPProxyWrapHandler(t)
	// Plain request with no JSON-RPC routing state attached.
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	originalBody := []byte(`{"hello":"world"}`)
	res := makeResponse(http.StatusOK, "application/json", originalBody, nil)

	require.NoError(t, h.HandleResponse(nil, res, req, nil))

	got, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Equal(t, originalBody, got, "response must be untouched when not a tools/call")
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestMCPProxyResponseWrap_NoIDStashed_NoWrap(t *testing.T) {
	// Request was not a tools/call (MCPHandler did not stash a JSON-RPC id);
	// the wrap MUST be a transparent passthrough so non-tools/call traffic
	// (initialize / tools/list / ping / non-MCP-Proxy responses) is unchanged.
	h := buildMCPProxyWrapHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	originalBody := []byte(`{"x":1}`)
	res := makeResponse(http.StatusOK, "application/json", originalBody, nil)

	require.NoError(t, h.HandleResponse(nil, res, req, nil))

	got, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Equal(t, originalBody, got)
}

func TestMCPProxyResponseWrap_MalformedJSON_StillWrapsAsSuccess(t *testing.T) {
	// 2xx with declared JSON content-type but unparseable body: the success
	// envelope is still emitted, structuredContent is omitted, and the raw
	// bytes appear as the text content.
	h := buildMCPProxyWrapHandler(t)
	req := makeToolsCallRequest(t, float64(9), "tool")
	body := []byte(`{"oops":`) // truncated/invalid JSON
	res := makeResponse(http.StatusOK, "application/json", body, nil)

	require.NoError(t, h.HandleResponse(nil, res, req, nil))

	env := readEnvelope(t, res)
	result := env["result"].(map[string]any)
	assert.Equal(t, false, result["isError"])
	_, hasSC := result["structuredContent"]
	assert.False(t, hasSC, "structuredContent should be omitted when JSON body fails to parse")
	c0 := result["content"].([]any)[0].(map[string]any)
	assert.Equal(t, string(body), c0["text"])
}

func TestMCPProxyResponseWrap_ReadError_ProducesUpstreamErrorEnvelope(t *testing.T) {
	// Simulate an upstream that sets a non-2xx status and whose body reader
	// returns an error mid-stream. The handler must still emit a valid
	// JSON-RPC error envelope rather than propagating the read error.
	h := buildMCPProxyWrapHandler(t)
	req := makeToolsCallRequest(t, float64(10), "tool")

	res := &http.Response{
		StatusCode: http.StatusBadGateway,
		Status:     http.StatusText(http.StatusBadGateway),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(&errorReader{}),
	}

	require.NoError(t, h.HandleResponse(nil, res, req, nil))

	assert.Equal(t, http.StatusOK, res.StatusCode)
	env := readEnvelope(t, res)
	result := env["result"].(map[string]any)
	assert.Equal(t, true, result["isError"])
	sc := result["structuredContent"].(map[string]any)
	// The defensive branch maps to upstream_5xx (status 502) or
	// upstream_error depending on the upstream status; here it is 502.
	assert.Contains(t, []string{"upstream_5xx", "upstream_error"}, sc["kind"])
}

func TestMCPProxyResponseWrap_Enabled(t *testing.T) {
	// Enabled() must be true for MCP APIs and false otherwise.
	mcpHandler := buildMCPProxyWrapHandler(t)
	assert.True(t, mcpHandler.Enabled())

	nonMCP := &MCPProxyResponseWrap{
		BaseTykResponseHandler: BaseTykResponseHandler{
			Spec: &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "x"}},
		},
	}
	assert.False(t, nonMCP.Enabled())
}

func TestMCPProxyResponseWrap_BodyExcerptTruncatedTo1KiB(t *testing.T) {
	h := buildMCPProxyWrapHandler(t)
	req := makeToolsCallRequest(t, float64(11), "tool")
	big := bytes.Repeat([]byte("A"), 4096) // 4 KiB
	res := makeResponse(http.StatusBadRequest, "text/plain", big, nil)

	require.NoError(t, h.HandleResponse(nil, res, req, nil))

	env := readEnvelope(t, res)
	sc := env["result"].(map[string]any)["structuredContent"].(map[string]any)
	excerpt := sc["body_excerpt"].(string)
	assert.LessOrEqual(t, len(excerpt), 1024, "body_excerpt must be ≤ 1 KiB per RFC §8.5")
}

func TestMCPProxyResponseWrap_Headers(t *testing.T) {
	h := buildMCPProxyWrapHandler(t)
	req := makeToolsCallRequest(t, float64(12), "tool")
	body := []byte(`{"k":"v"}`)
	res := makeResponse(http.StatusOK, "application/json", body, nil)
	res.Header.Set("Content-Encoding", "gzip") // must be cleared

	require.NoError(t, h.HandleResponse(nil, res, req, nil))

	assert.Equal(t, "application/json", res.Header.Get("Content-Type"))
	assert.Equal(t, "", res.Header.Get("Content-Encoding"))

	cl, err := strconv.Atoi(res.Header.Get("Content-Length"))
	require.NoError(t, err)
	assert.EqualValues(t, cl, res.ContentLength)
}

// errorReader always fails on Read — used to simulate a torn upstream stream.
type errorReader struct{}

func (errorReader) Read(_ []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}
