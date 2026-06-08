package adapter

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
			ParamSourceNames: map[string]string{
				"id":      "id",
				"verbose": "verbose",
			},
			ParamOrder: []string{"id", "verbose"},
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"id": map[string]any{"type": "string"}},
				"required":   []string{"id"},
			},
			Annotations: &oas.DerivedToolAnnotations{
				Title:           "Get order",
				ReadOnlyHint:    boolPtr(true),
				DestructiveHint: boolPtr(false),
				IdempotentHint:  boolPtr(true),
				OpenWorldHint:   boolPtr(false),
			},
			OutputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{"type": "string"},
				},
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

func boolPtr(v bool) *bool {
	return &v
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

func TestBuildUpstreamRequest_RejectsUnknownArgs(t *testing.T) {
	t.Parallel()
	parent := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
	tool := sampleTool(t, "getOrder")

	_, err := BuildUpstreamRequest(parent, tool, "rest-1", map[string]any{
		"id":      42,
		"unknown": "rejected",
	})

	require.Error(t, err)
	assert.True(t, IsInvalidParams(err))
	assert.Contains(t, err.Error(), `unknown argument "unknown"`)
}

func TestBuildUpstreamRequest_QueryParametersUseDerivedOrder(t *testing.T) {
	t.Parallel()
	parent := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
	tool := &oas.DerivedTool{
		Name:         "list_orders",
		Method:       http.MethodGet,
		PathTemplate: "/orders",
		ParamLocations: map[string]string{
			"z_last":  oas.DerivedParamLocationQuery,
			"a_first": oas.DerivedParamLocationQuery,
			"middle":  oas.DerivedParamLocationQuery,
		},
		ParamSourceNames: map[string]string{
			"z_last":  "z",
			"a_first": "a",
			"middle":  "m",
		},
		ParamOrder: []string{"z_last", "a_first", "middle"},
	}

	req, err := BuildUpstreamRequest(parent, tool, "rest-1", map[string]any{
		"a_first": "1",
		"middle":  "2",
		"z_last":  "3",
	})
	require.NoError(t, err)

	assert.Equal(t, "z=3&a=1&m=2", req.URL.RawQuery)
}

func TestBuildUpstreamRequest_QueryArrayParametersUseSerializationMetadata(t *testing.T) {
	t.Parallel()
	parent := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
	tool := &oas.DerivedTool{
		Name:         "list_orders",
		Method:       http.MethodGet,
		PathTemplate: "/orders",
		ParamLocations: map[string]string{
			"tags":       oas.DerivedParamLocationQuery,
			"ids":        oas.DerivedParamLocationQuery,
			"pipe_names": oas.DerivedParamLocationQuery,
		},
		ParamSourceNames: map[string]string{
			"tags":       "tag",
			"ids":        "ids",
			"pipe_names": "names",
		},
		ParamSerializations: map[string]oas.DerivedParamSerialization{
			"tags":       {SourceName: "tag", Location: oas.DerivedParamLocationQuery, Style: "form", Explode: true, SchemaType: "array"},
			"ids":        {SourceName: "ids", Location: oas.DerivedParamLocationQuery, Style: "form", Explode: false, SchemaType: "array"},
			"pipe_names": {SourceName: "names", Location: oas.DerivedParamLocationQuery, Style: "pipeDelimited", Explode: false, SchemaType: "array"},
		},
		ParamOrder: []string{"tags", "ids", "pipe_names"},
	}

	req, err := BuildUpstreamRequest(parent, tool, "rest-1", map[string]any{
		"tags":       []any{"new", "paid"},
		"ids":        []any{1, 2},
		"pipe_names": []any{"alice", "bob"},
	})
	require.NoError(t, err)

	query := req.URL.Query()
	assert.Equal(t, []string{"new", "paid"}, query["tag"])
	assert.Equal(t, "1,2", query.Get("ids"))
	assert.Equal(t, "alice|bob", query.Get("names"))
	assert.Equal(t, "tag=new&tag=paid&ids=1%2C2&names=alice%7Cbob", req.URL.RawQuery)
}

func TestBuildUpstreamRequest_HeaderArrayParametersUseSerializationMetadata(t *testing.T) {
	t.Parallel()
	parent := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
	tool := &oas.DerivedTool{
		Name:         "list_orders",
		Method:       http.MethodGet,
		PathTemplate: "/orders",
		ParamLocations: map[string]string{
			"states": oas.DerivedParamLocationHeader,
		},
		ParamSourceNames: map[string]string{
			"states": "X-States",
		},
		ParamSerializations: map[string]oas.DerivedParamSerialization{
			"states": {SourceName: "X-States", Location: oas.DerivedParamLocationHeader, Style: "simple", Explode: false, SchemaType: "array"},
		},
	}

	req, err := BuildUpstreamRequest(parent, tool, "rest-1", map[string]any{
		"states": []any{"open", "closed"},
	})
	require.NoError(t, err)

	assert.Equal(t, "open,closed", req.Header.Get("X-States"))
}

func TestBuildUpstreamRequest_RejectsNonScalarPathQueryAndHeaderValues(t *testing.T) {
	t.Parallel()
	parent := httptest.NewRequest(http.MethodPost, "/mcp/", nil)

	tests := []struct {
		name string
		tool *oas.DerivedTool
		args map[string]any
	}{
		{
			name: "path object",
			tool: &oas.DerivedTool{
				Name:         "get_order",
				Method:       http.MethodGet,
				PathTemplate: "/orders/{id}",
				ParamLocations: map[string]string{
					"id": oas.DerivedParamLocationPath,
				},
			},
			args: map[string]any{"id": map[string]any{"nested": "value"}},
		},
		{
			name: "query object",
			tool: &oas.DerivedTool{
				Name:         "list_orders",
				Method:       http.MethodGet,
				PathTemplate: "/orders",
				ParamLocations: map[string]string{
					"filter": oas.DerivedParamLocationQuery,
				},
			},
			args: map[string]any{"filter": map[string]any{"status": "open"}},
		},
		{
			name: "header object",
			tool: &oas.DerivedTool{
				Name:         "list_orders",
				Method:       http.MethodGet,
				PathTemplate: "/orders",
				ParamLocations: map[string]string{
					"filter": oas.DerivedParamLocationHeader,
				},
			},
			args: map[string]any{"filter": map[string]any{"status": "open"}},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := BuildUpstreamRequest(parent, tt.tool, "rest-1", tt.args)
			require.Error(t, err)
			assert.True(t, IsInvalidParams(err))
			assert.Contains(t, err.Error(), "cannot serialize")
		})
	}
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

func TestBuildUpstreamRequest_UsesSourceNamesForRenamedArguments(t *testing.T) {
	t.Parallel()
	parent := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
	tool := &oas.DerivedTool{
		Name:         "get_order",
		Method:       http.MethodGet,
		PathTemplate: "/orders/{id}",
		ParamLocations: map[string]string{
			"path_id":  "path",
			"query_id": "query",
		},
		ParamSourceNames: map[string]string{
			"path_id":  "id",
			"query_id": "id",
		},
	}

	req, err := BuildUpstreamRequest(parent, tool, "rest-1", map[string]any{
		"path_id":  42,
		"query_id": "query-value",
	})
	require.NoError(t, err)

	assert.Equal(t, "/orders/42", req.URL.Path)
	assert.Equal(t, "query-value", req.URL.Query().Get("id"))
}

func TestBuildUpstreamRequest_FormURLEncodedBodyFields(t *testing.T) {
	t.Parallel()
	parent := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
	tool := &oas.DerivedTool{
		Name:                   "submit_order",
		Method:                 http.MethodPost,
		PathTemplate:           "/orders",
		RequestBodyContentType: "application/x-www-form-urlencoded",
		ParamLocations: map[string]string{
			"sku": "body.sku",
			"qty": "body.qty",
		},
	}

	req, err := BuildUpstreamRequest(parent, tool, "rest-1", map[string]any{
		"sku": "ABC",
		"qty": 5,
	})
	require.NoError(t, err)
	assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))

	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	form, err := url.ParseQuery(string(body))
	require.NoError(t, err)
	assert.Equal(t, "ABC", form.Get("sku"))
	assert.Equal(t, "5", form.Get("qty"))
}

func TestBuildUpstreamRequest_PreservesConfiguredJSONBodyContentType(t *testing.T) {
	t.Parallel()
	parent := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
	tool := &oas.DerivedTool{
		Name:                   "create_order",
		Method:                 http.MethodPost,
		PathTemplate:           "/orders",
		RequestBodyContentType: "application/vnd.api+json",
		ParamLocations: map[string]string{
			"data": oas.DerivedParamLocationBodyPrefix + "data",
		},
	}

	req, err := BuildUpstreamRequest(parent, tool, "rest-1", map[string]any{
		"data": "ABC",
	})
	require.NoError(t, err)

	assert.Equal(t, "application/vnd.api+json", req.Header.Get("Content-Type"))
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

	_, err := BuildUpstreamRequest(parent, tool, "rest-1", map[string]any{"body": "not-an-object"})

	require.Error(t, err)
	assert.True(t, IsInvalidParams(err))
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
		{name: "null", body: nil, want: `null`},
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

func TestRecorder_CustomBodyLimit(t *testing.T) {
	t.Parallel()
	rec := NewRecorderWithBodyLimit(16)

	_, err := rec.Write([]byte("0123456789abcdefEXTRA"))
	require.NoError(t, err)

	assert.True(t, rec.Truncated())
	assert.Equal(t, "0123456789abcdef", string(rec.Body()))
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
	assert.Contains(t, text, "The content above is incomplete.")
	assert.True(t, strings.HasPrefix(text, strings.Repeat("x", BodyTruncationBytes)))
	assert.True(t, strings.HasSuffix(text, "Tyk truncated the upstream response after 1048576 bytes. The content above is incomplete."))
}
