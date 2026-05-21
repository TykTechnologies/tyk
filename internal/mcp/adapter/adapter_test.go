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

func sampleTool(t *testing.T, name string) *oas.DerivedTool {
	t.Helper()
	tools := sampleTools()
	for i := range tools {
		if tools[i].Name == name {
			return &tools[i]
		}
	}
	t.Fatalf("sample tool %q not found", name)
	return nil
}

func TestBuildUpstreamRequest_PathQueryHeader(t *testing.T) {
	t.Parallel()
	parent := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
	tool := sampleTool(t, "getOrder")

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

func TestBuildUpstreamRequest_IgnoresUnknownArgs(t *testing.T) {
	t.Parallel()
	parent := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
	tool := sampleTool(t, "getOrder")

	req, err := BuildUpstreamRequest(parent, tool, "rest-1", map[string]any{
		"id":      42,
		"unknown": "ignored",
	})
	require.NoError(t, err)

	assert.Equal(t, "/orders/42", req.URL.Path)
	assert.Empty(t, req.URL.Query().Get("unknown"))
}

func TestBuildUpstreamRequest_BodyFields(t *testing.T) {
	t.Parallel()
	parent := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
	tool := sampleTool(t, "createOrder")

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
	tool := sampleTool(t, "getOrder")

	_, err := BuildUpstreamRequest(parent, tool, "rest-1", map[string]any{"verbose": "yes"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required path parameter")
}

func TestBuildUpstreamRequest_RejectsWholeBodyAndBodyFieldCombination(t *testing.T) {
	t.Parallel()
	parent := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
	tool := &oas.DerivedTool{
		Name:         "mixedBody",
		Method:       http.MethodPost,
		PathTemplate: "/orders",
		ParamLocations: map[string]string{
			"body": "body",
			"sku":  "body.sku",
		},
	}

	_, err := BuildUpstreamRequest(parent, tool, "rest-1", map[string]any{
		"body": "not-an-object",
		"sku":  "ABC",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be combined with whole-body argument")
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

func TestRecorder_WriteHeaderKeepsFirstStatus(t *testing.T) {
	t.Parallel()
	rec := NewRecorder()

	rec.WriteHeader(http.StatusAccepted)
	rec.WriteHeader(http.StatusTeapot)

	assert.Equal(t, http.StatusAccepted, rec.Status())
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
	content := env["content"].([]any)[0].(map[string]any)
	text := content["text"].(string)
	assert.Contains(t, text, "Tyk truncated the upstream response")
	assert.Contains(t, text, "The content below is incomplete.")
	assert.True(t, strings.HasSuffix(text, strings.Repeat("x", BodyTruncationBytes)))
}
