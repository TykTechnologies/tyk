package adapter

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

func sampleTools() []oas.DerivedTool {
	return []oas.DerivedTool{
		{
			Name:           "getOrder",
			Description:    "fetch an order",
			Method:         http.MethodGet,
			PathTemplate:   "/orders/{id}",
			ParamLocations: map[string]string{"id": "path", "verbose": "query"},
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"id": map[string]any{"type": "string"}},
				"required":   []string{"id"},
			},
		},
		{
			Name:         "createOrder",
			Method:       http.MethodPost,
			PathTemplate: "/orders",
			ParamLocations: map[string]string{
				"sku":   "body.sku",
				"qty":   "body.qty",
				"trace": "header",
			},
		},
	}
}

func TestFindTool(t *testing.T) {
	t.Parallel()
	tools := sampleTools()

	got := FindTool(tools, "getOrder")
	require.NotNil(t, got)
	assert.Equal(t, "GET", got.Method)

	assert.Nil(t, FindTool(tools, "unknown"))
}

func TestInitializeResult(t *testing.T) {
	t.Parallel()
	res := InitializeResult("Orders [MCP adapter]")
	assert.Equal(t, ProtocolVersion, res["protocolVersion"])
	info := res["serverInfo"].(map[string]any)
	assert.Equal(t, "Orders [MCP adapter]", info["name"])
}

func TestToolsListResult(t *testing.T) {
	t.Parallel()
	res := ToolsListResult(sampleTools())
	items := res["tools"].([]map[string]any)
	require.Len(t, items, 2)
	assert.Equal(t, "getOrder", items[0]["name"])
	assert.Equal(t, "fetch an order", items[0]["description"])
	// createOrder has no description; field must be omitted.
	_, has := items[1]["description"]
	assert.False(t, has, "empty description should be omitted")
}

func TestBuildUpstreamRequest_PathQueryHeader(t *testing.T) {
	t.Parallel()
	parent := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
	tool := FindTool(sampleTools(), "getOrder")

	req, err := BuildUpstreamRequest(parent, tool, "rest-1", map[string]any{
		"id":      42,
		"verbose": "true",
	})
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, req.Method)
	assert.Equal(t, "/orders/42", req.URL.Path)
	assert.Equal(t, "true", req.URL.Query().Get("verbose"))
	assert.Equal(t, "rest-1", req.URL.Host)
	assert.Equal(t, "http", req.URL.Scheme)
}

func TestBuildUpstreamRequest_BodyFields(t *testing.T) {
	t.Parallel()
	parent := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
	tool := FindTool(sampleTools(), "createOrder")

	req, err := BuildUpstreamRequest(parent, tool, "rest-1", map[string]any{
		"sku":   "ABC",
		"qty":   5,
		"trace": "tid-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "tid-1", req.Header.Get("trace"))
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))

	var b bytes.Buffer
	_, err = b.ReadFrom(req.Body)
	require.NoError(t, err)
	var body map[string]any
	require.NoError(t, json.Unmarshal(b.Bytes(), &body))
	assert.Equal(t, "ABC", body["sku"])
	assert.EqualValues(t, 5, body["qty"])
}

func TestBuildUpstreamRequest_MissingPathParam(t *testing.T) {
	t.Parallel()
	parent := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
	tool := FindTool(sampleTools(), "getOrder")

	_, err := BuildUpstreamRequest(parent, tool, "rest-1", map[string]any{"verbose": "yes"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required path parameter")
}

func TestBuildUpstreamRequest_WholeBodyAllowsAnyJSONValue(t *testing.T) {
	t.Parallel()
	parent := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
	tool := &oas.DerivedTool{
		Name:           "echo",
		Method:         http.MethodPost,
		PathTemplate:   "/echo",
		ParamLocations: map[string]string{"body": "body"},
	}

	cases := []struct {
		name string
		body any
		want string
	}{
		{name: "object", body: map[string]any{"ok": true}, want: `{"ok":true}`},
		{name: "array", body: []any{"a", float64(2), true}, want: `["a",2,true]`},
		{name: "string", body: "not-an-object", want: `"not-an-object"`},
		{name: "number", body: float64(42.5), want: `42.5`},
		{name: "boolean", body: true, want: `true`},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req, err := BuildUpstreamRequest(parent, tool, "rest-1", map[string]any{"body": tc.body})
			require.NoError(t, err)
			assert.Equal(t, "application/json", req.Header.Get("Content-Type"))

			var b bytes.Buffer
			_, err = b.ReadFrom(req.Body)
			require.NoError(t, err)
			assert.JSONEq(t, tc.want, b.String())
		})
	}
}

func TestRecorder_TruncationFlag(t *testing.T) {
	t.Parallel()
	rec := NewRecorder()
	// Write just under and just over the cap.
	_, err := rec.Write(bytes.Repeat([]byte("a"), BodyTruncationBytes-10))
	require.NoError(t, err)
	assert.False(t, rec.Truncated())
	_, err = rec.Write(bytes.Repeat([]byte("b"), 100))
	require.NoError(t, err)
	assert.True(t, rec.Truncated())
	assert.Equal(t, BodyTruncationBytes, len(rec.Body()))
}

func TestRecorder_StatusAndContentType(t *testing.T) {
	t.Parallel()
	rec := NewRecorder()
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusTeapot)
	_, err := rec.Write([]byte(`{"ok":true}`))
	require.NoError(t, err)

	assert.Equal(t, http.StatusTeapot, rec.Status())
	assert.Equal(t, "application/json", rec.ContentType())
	assert.Equal(t, `{"ok":true}`, string(rec.Body()))
}

func TestToolResultEnvelope(t *testing.T) {
	t.Parallel()
	rec := NewRecorder()
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusBadRequest)
	_, err := rec.Write([]byte(`{"error":"x"}`))
	require.NoError(t, err)

	env := ToolResultEnvelope(rec)
	assert.True(t, env["isError"].(bool))
	meta := env["_meta"].(map[string]any)
	assert.Equal(t, http.StatusBadRequest, meta["upstreamHttpStatus"])
	content := env["content"].([]any)[0].(map[string]any)
	assert.Equal(t, "text", content["type"])
	assert.Equal(t, `{"error":"x"}`, content["text"])
}

func TestToolResultEnvelope_Truncation(t *testing.T) {
	t.Parallel()
	rec := NewRecorder()
	_, err := rec.Write(bytes.Repeat([]byte("x"), BodyTruncationBytes+1))
	require.NoError(t, err)
	env := ToolResultEnvelope(rec)
	meta := env["_meta"].(map[string]any)
	assert.Equal(t, true, meta["truncated"])
}

func TestJSONRPCResultRoundTrip(t *testing.T) {
	t.Parallel()
	raw := JSONRPCResult("abc", map[string]any{"hello": "world"})
	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, "2.0", got["jsonrpc"])
	assert.Equal(t, "abc", got["id"])
	assert.Equal(t, "world", got["result"].(map[string]any)["hello"])
}

func TestJSONRPCErrorEncoding(t *testing.T) {
	t.Parallel()
	raw := JSONRPCError(1, JSONRPCMethodNotFound, "no such tool")
	assert.True(t, strings.Contains(string(raw), `"code":-32601`))
	assert.True(t, strings.Contains(string(raw), "no such tool"))
}

func TestWriteJSON(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	WriteJSON(rec, []byte(`{"k":1}`))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, `{"k":1}`, rec.Body.String())
}
