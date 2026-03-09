package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/user"
)

// buildMCPListFilterHandler creates a MCPListFilterResponseHandler for testing.
func buildMCPListFilterHandler(apiID string, isMCP bool) *MCPListFilterResponseHandler {
	proto := ""
	if isMCP {
		proto = apidef.AppProtocolMCP
	}
	return &MCPListFilterResponseHandler{
		BaseTykResponseHandler: BaseTykResponseHandler{
			Spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					APIID:               apiID,
					ApplicationProtocol: proto,
				},
			},
		},
	}
}

// makeToolsListResponse builds a JSON-RPC 2.0 response with a tools/list result.
func makeToolsListResponse(tools []map[string]any, nextCursor string) []byte {
	result := map[string]any{
		"tools": tools,
	}
	if nextCursor != "" {
		result["nextCursor"] = nextCursor
	}
	return makeJSONRPCResponse(1, result)
}

// makePromptsListResponse builds a JSON-RPC 2.0 response with a prompts/list result.
func makePromptsListResponse(prompts []map[string]any) []byte {
	result := map[string]any{
		"prompts": prompts,
	}
	return makeJSONRPCResponse(1, result)
}

// makeResourcesListResponse builds a JSON-RPC 2.0 response with a resources/list result.
func makeResourcesListResponse(resources []map[string]any) []byte {
	result := map[string]any{
		"resources": resources,
	}
	return makeJSONRPCResponse(1, result)
}

// makeResourceTemplatesListResponse builds a JSON-RPC 2.0 response with a resources/templates/list result.
func makeResourceTemplatesListResponse(templates []map[string]any) []byte {
	result := map[string]any{
		"resourceTemplates": templates,
	}
	return makeJSONRPCResponse(1, result)
}

// makeJSONRPCResponse builds a raw JSON-RPC 2.0 response envelope.
func makeJSONRPCResponse(id any, result any) []byte {
	resultBytes, _ := json.Marshal(result) //nolint:errcheck
	envelope := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  json.RawMessage(resultBytes),
	}
	b, _ := json.Marshal(envelope) //nolint:errcheck
	return b
}

// makeHTTPResponse creates an *http.Response with the given body bytes.
func makeHTTPResponse(body []byte) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

// readResponseBody reads and returns the body from an *http.Response.
func readResponseBody(t *testing.T, res *http.Response) []byte {
	t.Helper()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return body
}

// extractToolNames extracts the "name" fields from the tools array in a JSON-RPC response.
func extractToolNames(t *testing.T, body []byte) []string {
	t.Helper()
	var envelope mcp.JSONRPCResponse
	require.NoError(t, json.Unmarshal(body, &envelope))

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(envelope.Result, &result))

	var items []map[string]any
	require.NoError(t, json.Unmarshal(result["tools"], &items))

	names := make([]string, 0, len(items))
	for _, item := range items {
		if name, ok := item["name"].(string); ok {
			names = append(names, name)
		}
	}
	return names
}

// extractPromptNames extracts the "name" fields from the prompts array in a JSON-RPC response.
func extractPromptNames(t *testing.T, body []byte) []string {
	t.Helper()
	var envelope mcp.JSONRPCResponse
	require.NoError(t, json.Unmarshal(body, &envelope))

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(envelope.Result, &result))

	var items []map[string]any
	require.NoError(t, json.Unmarshal(result["prompts"], &items))

	names := make([]string, 0, len(items))
	for _, item := range items {
		if name, ok := item["name"].(string); ok {
			names = append(names, name)
		}
	}
	return names
}

// extractResourceURIs extracts the "uri" fields from the resources array in a JSON-RPC response.
func extractResourceURIs(t *testing.T, body []byte) []string {
	t.Helper()
	var envelope mcp.JSONRPCResponse
	require.NoError(t, json.Unmarshal(body, &envelope))

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(envelope.Result, &result))

	var items []map[string]any
	require.NoError(t, json.Unmarshal(result["resources"], &items))

	uris := make([]string, 0, len(items))
	for _, item := range items {
		if uri, ok := item["uri"].(string); ok {
			uris = append(uris, uri)
		}
	}
	return uris
}

// extractResourceTemplateURIs extracts the "uriTemplate" fields from the resourceTemplates array.
func extractResourceTemplateURIs(t *testing.T, body []byte) []string {
	t.Helper()
	var envelope mcp.JSONRPCResponse
	require.NoError(t, json.Unmarshal(body, &envelope))

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(envelope.Result, &result))

	var items []map[string]any
	require.NoError(t, json.Unmarshal(result["resourceTemplates"], &items))

	uris := make([]string, 0, len(items))
	for _, item := range items {
		if uri, ok := item["uriTemplate"].(string); ok {
			uris = append(uris, uri)
		}
	}
	return uris
}

func TestMCPListFilterResponseHandler_Enabled(t *testing.T) {
	t.Run("MCP API returns true", func(t *testing.T) {
		h := buildMCPListFilterHandler("api-1", true)
		assert.True(t, h.Enabled())
	})

	t.Run("non-MCP API returns false", func(t *testing.T) {
		h := buildMCPListFilterHandler("api-1", false)
		assert.False(t, h.Enabled())
	})
}

func TestMCPListFilterResponseHandler_Name(t *testing.T) {
	h := buildMCPListFilterHandler("api-1", true)
	assert.Equal(t, "MCPListFilterResponseHandler", h.Name())
}

func TestMCPListFilterResponseHandler_Init(t *testing.T) {
	h := &MCPListFilterResponseHandler{}
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:               "api-1",
			ApplicationProtocol: apidef.AppProtocolMCP,
		},
	}
	err := h.Init(nil, spec)
	require.NoError(t, err)
	assert.Equal(t, spec, h.Spec)
}

func TestMCPListFilterResponseHandler_HandleResponse(t *testing.T) {
	fourTools := []map[string]any{
		{"name": "get_weather", "description": "Get current weather"},
		{"name": "get_forecast", "description": "Get forecast"},
		{"name": "set_alert", "description": "Set weather alert"},
		{"name": "delete_alert", "description": "Delete weather alert"},
	}

	tests := []struct {
		name           string
		method         string
		session        *user.SessionState
		responseBody   []byte
		wantNames      []string // expected names after filtering (nil = skip name check)
		wantUnmodified bool     // if true, response body should be unchanged
		malformedJSON  bool     // if true, use byte comparison instead of JSONEq
	}{
		{
			name:   "tools/list filtered by allowlist",
			method: mcp.MethodToolsList,
			session: &user.SessionState{
				AccessRights: map[string]user.AccessDefinition{
					"api-1": {
						APIID: "api-1",
						MCPAccessRights: user.MCPAccessRights{
							Tools: user.AccessControlRules{
								Allowed: []string{"get_weather", "get_forecast"},
							},
						},
					},
				},
			},
			responseBody: makeToolsListResponse(fourTools, ""),
			wantNames:    []string{"get_weather", "get_forecast"},
		},
		{
			name:   "tools/list filtered by allowlist wildcard suffix",
			method: mcp.MethodToolsList,
			session: &user.SessionState{
				AccessRights: map[string]user.AccessDefinition{
					"api-1": {
						APIID: "api-1",
						MCPAccessRights: user.MCPAccessRights{
							Tools: user.AccessControlRules{
								Allowed: []string{"get_.*"},
							},
						},
					},
				},
			},
			responseBody: makeToolsListResponse(fourTools, ""),
			wantNames:    []string{"get_weather", "get_forecast"},
		},
		{
			name:   "tools/list filtered by denylist",
			method: mcp.MethodToolsList,
			session: &user.SessionState{
				AccessRights: map[string]user.AccessDefinition{
					"api-1": {
						APIID: "api-1",
						MCPAccessRights: user.MCPAccessRights{
							Tools: user.AccessControlRules{
								Blocked: []string{"delete_alert", "set_alert"},
							},
						},
					},
				},
			},
			responseBody: makeToolsListResponse(fourTools, ""),
			wantNames:    []string{"get_weather", "get_forecast"},
		},
		{
			name:   "tools/list filtered by denylist wildcard prefix",
			method: mcp.MethodToolsList,
			session: &user.SessionState{
				AccessRights: map[string]user.AccessDefinition{
					"api-1": {
						APIID: "api-1",
						MCPAccessRights: user.MCPAccessRights{
							Tools: user.AccessControlRules{
								Blocked: []string{".*_alert"},
							},
						},
					},
				},
			},
			responseBody: makeToolsListResponse(fourTools, ""),
			wantNames:    []string{"get_weather", "get_forecast"},
		},
		{
			name:   "tools/list deny takes precedence over allow",
			method: mcp.MethodToolsList,
			session: &user.SessionState{
				AccessRights: map[string]user.AccessDefinition{
					"api-1": {
						APIID: "api-1",
						MCPAccessRights: user.MCPAccessRights{
							Tools: user.AccessControlRules{
								Blocked: []string{"delete_alert", "set_alert"},
								Allowed: []string{"set_alert"},
							},
						},
					},
				},
			},
			responseBody: makeToolsListResponse(fourTools, ""),
			wantNames:    []string{},
		},
		{
			name:   "tools/list pagination nextCursor preserved",
			method: mcp.MethodToolsList,
			session: &user.SessionState{
				AccessRights: map[string]user.AccessDefinition{
					"api-1": {
						APIID: "api-1",
						MCPAccessRights: user.MCPAccessRights{
							Tools: user.AccessControlRules{
								Allowed: []string{"get_weather"},
							},
						},
					},
				},
			},
			responseBody: makeToolsListResponse(fourTools, "cursor-abc-123"),
			wantNames:    []string{"get_weather"},
		},
		{
			name:   "prompts/list filtered by allowlist",
			method: mcp.MethodPromptsList,
			session: &user.SessionState{
				AccessRights: map[string]user.AccessDefinition{
					"api-1": {
						APIID: "api-1",
						MCPAccessRights: user.MCPAccessRights{
							Prompts: user.AccessControlRules{
								Allowed: []string{"summarise", "translate"},
							},
						},
					},
				},
			},
			responseBody: makePromptsListResponse([]map[string]any{
				{"name": "summarise", "description": "Summarise text"},
				{"name": "translate", "description": "Translate text"},
				{"name": "greet", "description": "Greet user"},
			}),
		},
		{
			name:   "resources/templates/list filtered by denylist",
			method: mcp.MethodResourcesTemplatesList,
			session: &user.SessionState{
				AccessRights: map[string]user.AccessDefinition{
					"api-1": {
						APIID: "api-1",
						MCPAccessRights: user.MCPAccessRights{
							Resources: user.AccessControlRules{
								Blocked: []string{`db://\{schema\}/\{table\}`},
							},
						},
					},
				},
			},
			responseBody: makeResourceTemplatesListResponse([]map[string]any{
				{"uriTemplate": "file://{path}", "name": "File"},
				{"uriTemplate": "db://{schema}/{table}", "name": "Database"},
			}),
		},
		{
			name:   "resources/list filtered by allowlist",
			method: mcp.MethodResourcesList,
			session: &user.SessionState{
				AccessRights: map[string]user.AccessDefinition{
					"api-1": {
						APIID: "api-1",
						MCPAccessRights: user.MCPAccessRights{
							Resources: user.AccessControlRules{
								Allowed: []string{"file:///public/.*"},
							},
						},
					},
				},
			},
			responseBody: makeResourcesListResponse([]map[string]any{
				{"uri": "file:///public/readme.md", "name": "Readme"},
				{"uri": "file:///secret/keys.txt", "name": "Keys"},
				{"uri": "file:///public/docs.md", "name": "Docs"},
			}),
		},
		{
			name:   "no filtering when MCPAccessRights is empty",
			method: mcp.MethodToolsList,
			session: &user.SessionState{
				AccessRights: map[string]user.AccessDefinition{
					"api-1": {APIID: "api-1"},
				},
			},
			responseBody:   makeToolsListResponse(fourTools, ""),
			wantUnmodified: true,
		},
		{
			name:           "no filtering when session is nil",
			method:         mcp.MethodToolsList,
			session:        nil,
			responseBody:   makeToolsListResponse(fourTools, ""),
			wantUnmodified: true,
		},
		{
			name:   "no filtering for non-list method tools/call",
			method: mcp.MethodToolsCall,
			session: &user.SessionState{
				AccessRights: map[string]user.AccessDefinition{
					"api-1": {
						APIID: "api-1",
						MCPAccessRights: user.MCPAccessRights{
							Tools: user.AccessControlRules{
								Blocked: []string{".*"},
							},
						},
					},
				},
			},
			responseBody:   makeToolsListResponse(fourTools, ""),
			wantUnmodified: true,
		},
		{
			name:   "no filtering for non-list method ping",
			method: "ping",
			session: &user.SessionState{
				AccessRights: map[string]user.AccessDefinition{
					"api-1": {
						APIID: "api-1",
						MCPAccessRights: user.MCPAccessRights{
							Tools: user.AccessControlRules{
								Blocked: []string{".*"},
							},
						},
					},
				},
			},
			responseBody:   []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`),
			wantUnmodified: true,
		},
		{
			name:   "empty tools array stays empty",
			method: mcp.MethodToolsList,
			session: &user.SessionState{
				AccessRights: map[string]user.AccessDefinition{
					"api-1": {
						APIID: "api-1",
						MCPAccessRights: user.MCPAccessRights{
							Tools: user.AccessControlRules{
								Allowed: []string{"get_weather"},
							},
						},
					},
				},
			},
			responseBody: makeToolsListResponse([]map[string]any{}, ""),
			wantNames:    []string{},
		},
		{
			name:   "malformed JSON response passes through unmodified",
			method: mcp.MethodToolsList,
			session: &user.SessionState{
				AccessRights: map[string]user.AccessDefinition{
					"api-1": {
						APIID: "api-1",
						MCPAccessRights: user.MCPAccessRights{
							Tools: user.AccessControlRules{
								Blocked: []string{".*"},
							},
						},
					},
				},
			},
			responseBody:   []byte(`{this is not valid json`),
			wantUnmodified: true,
			malformedJSON:  true,
		},
		{
			name:   "error response with no result passes through unmodified",
			method: mcp.MethodToolsList,
			session: &user.SessionState{
				AccessRights: map[string]user.AccessDefinition{
					"api-1": {
						APIID: "api-1",
						MCPAccessRights: user.MCPAccessRights{
							Tools: user.AccessControlRules{
								Blocked: []string{".*"},
							},
						},
					},
				},
			},
			responseBody:   []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"invalid request"}}`),
			wantUnmodified: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := buildMCPListFilterHandler("api-1", true)
			rw := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{
				Method: tt.method,
				ID:     1,
			})

			res := makeHTTPResponse(tt.responseBody)
			originalBody := make([]byte, len(tt.responseBody))
			copy(originalBody, tt.responseBody)

			err := h.HandleResponse(rw, res, req, tt.session)
			require.NoError(t, err)

			body := readResponseBody(t, res)

			if tt.wantUnmodified {
				if tt.malformedJSON {
					assert.Equal(t, originalBody, body,
						"response body should be byte-identical for malformed JSON")
				} else {
					assert.JSONEq(t, string(originalBody), string(body),
						"response body should be unmodified")
				}
				return
			}

			// For specific name checks.
			if tt.wantNames != nil {
				switch tt.method {
				case mcp.MethodToolsList:
					got := extractToolNames(t, body)
					assert.Equal(t, tt.wantNames, got)
				case mcp.MethodPromptsList:
					got := extractPromptNames(t, body)
					assert.Equal(t, tt.wantNames, got)
				case mcp.MethodResourcesList:
					got := extractResourceURIs(t, body)
					assert.Equal(t, tt.wantNames, got)
				case mcp.MethodResourcesTemplatesList:
					got := extractResourceTemplateURIs(t, body)
					assert.Equal(t, tt.wantNames, got)
				}
			}

			// Verify pagination cursor is preserved when applicable.
			if tt.name == "tools/list pagination nextCursor preserved" {
				var envelope mcp.JSONRPCResponse
				require.NoError(t, json.Unmarshal(body, &envelope))
				var result map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(envelope.Result, &result))
				cursorRaw, exists := result["nextCursor"]
				require.True(t, exists, "nextCursor should be preserved in filtered response")
				var cursor string
				require.NoError(t, json.Unmarshal(cursorRaw, &cursor))
				assert.Equal(t, "cursor-abc-123", cursor)
			}
		})
	}
}

func TestMCPListFilterResponseHandler_HandleResponse_PromptsListFiltering(t *testing.T) {
	h := buildMCPListFilterHandler("api-1", true)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{
		Method: mcp.MethodPromptsList,
		ID:     1,
	})

	prompts := []map[string]any{
		{"name": "summarise", "description": "Summarise text"},
		{"name": "translate", "description": "Translate text"},
		{"name": "greet", "description": "Greet user"},
	}

	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Prompts: user.AccessControlRules{
						Allowed: []string{"summarise", "translate"},
					},
				},
			},
		},
	}

	res := makeHTTPResponse(makePromptsListResponse(prompts))
	err := h.HandleResponse(rw, res, req, session)
	require.NoError(t, err)

	body := readResponseBody(t, res)
	got := extractPromptNames(t, body)
	assert.Equal(t, []string{"summarise", "translate"}, got)
}

func TestMCPListFilterResponseHandler_HandleResponse_ResourceTemplatesFiltering(t *testing.T) {
	h := buildMCPListFilterHandler("api-1", true)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{
		Method: mcp.MethodResourcesTemplatesList,
		ID:     1,
	})

	templates := []map[string]any{
		{"uriTemplate": "file://{path}", "name": "File"},
		{"uriTemplate": "db://{schema}/{table}", "name": "Database"},
	}

	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Resources: user.AccessControlRules{
						Blocked: []string{`db://\{schema\}/\{table\}`},
					},
				},
			},
		},
	}

	res := makeHTTPResponse(makeResourceTemplatesListResponse(templates))
	err := h.HandleResponse(rw, res, req, session)
	require.NoError(t, err)

	body := readResponseBody(t, res)
	got := extractResourceTemplateURIs(t, body)
	assert.Equal(t, []string{"file://{path}"}, got)
}

func TestMCPListFilterResponseHandler_HandleResponse_ResourcesFiltering(t *testing.T) {
	h := buildMCPListFilterHandler("api-1", true)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{
		Method: mcp.MethodResourcesList,
		ID:     1,
	})

	resources := []map[string]any{
		{"uri": "file:///public/readme.md", "name": "Readme"},
		{"uri": "file:///secret/keys.txt", "name": "Keys"},
		{"uri": "file:///public/docs.md", "name": "Docs"},
	}

	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Resources: user.AccessControlRules{
						Allowed: []string{"file:///public/.*"},
					},
				},
			},
		},
	}

	res := makeHTTPResponse(makeResourcesListResponse(resources))
	err := h.HandleResponse(rw, res, req, session)
	require.NoError(t, err)

	body := readResponseBody(t, res)
	got := extractResourceURIs(t, body)
	assert.Equal(t, []string{"file:///public/readme.md", "file:///public/docs.md"}, got)
}

func TestMCPListFilterResponseHandler_HandleResponse_NoRoutingState(t *testing.T) {
	h := buildMCPListFilterHandler("api-1", true)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	// No routing state set.

	responseBody := makeToolsListResponse([]map[string]any{
		{"name": "tool_a"},
	}, "")

	res := makeHTTPResponse(responseBody)
	err := h.HandleResponse(rw, res, req, nil)
	require.NoError(t, err)

	body := readResponseBody(t, res)
	assert.JSONEq(t, string(responseBody), string(body))
}

func TestMCPListFilterResponseHandler_HandleResponse_NilBody(t *testing.T) {
	h := buildMCPListFilterHandler("api-1", true)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{
		Method: mcp.MethodToolsList,
		ID:     1,
	})

	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Tools: user.AccessControlRules{Blocked: []string{".*"}},
				},
			},
		},
	}

	res := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       nil,
	}

	err := h.HandleResponse(rw, res, req, session)
	require.NoError(t, err)
}

func TestMCPListFilterResponseHandler_HandleResponse_EmptyBody(t *testing.T) {
	h := buildMCPListFilterHandler("api-1", true)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{
		Method: mcp.MethodToolsList,
		ID:     1,
	})

	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Tools: user.AccessControlRules{Blocked: []string{".*"}},
				},
			},
		},
	}

	res := makeHTTPResponse([]byte{})
	err := h.HandleResponse(rw, res, req, session)
	require.NoError(t, err)

	body := readResponseBody(t, res)
	assert.Empty(t, body)
}

func TestMCPListFilterResponseHandler_HandleResponse_ContentLengthUpdated(t *testing.T) {
	h := buildMCPListFilterHandler("api-1", true)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{
		Method: mcp.MethodToolsList,
		ID:     1,
	})

	tools := []map[string]any{
		{"name": "keep_me", "description": "Keep this tool"},
		{"name": "remove_me", "description": "Remove this tool"},
	}

	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Tools: user.AccessControlRules{
						Allowed: []string{"keep_me"},
					},
				},
			},
		},
	}

	res := makeHTTPResponse(makeToolsListResponse(tools, ""))
	err := h.HandleResponse(rw, res, req, session)
	require.NoError(t, err)

	body := readResponseBody(t, res)
	assert.Equal(t, int64(len(body)), res.ContentLength,
		"Content-Length should match actual body size")
	assert.Equal(t, fmt.Sprintf("%d", len(body)), res.Header.Get("Content-Length"),
		"Content-Length header should match actual body size")
}

func TestMCPListFilterResponseHandler_HandleResponse_WrongAPIID(t *testing.T) {
	h := buildMCPListFilterHandler("api-1", true)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{
		Method: mcp.MethodToolsList,
		ID:     1,
	})

	tools := []map[string]any{
		{"name": "tool_a"},
		{"name": "tool_b"},
	}
	responseBody := makeToolsListResponse(tools, "")

	// Session has access rights for a different API ID.
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-2": {
				APIID: "api-2",
				MCPAccessRights: user.MCPAccessRights{
					Tools: user.AccessControlRules{
						Blocked: []string{".*"},
					},
				},
			},
		},
	}

	res := makeHTTPResponse(responseBody)
	err := h.HandleResponse(rw, res, req, session)
	require.NoError(t, err)

	body := readResponseBody(t, res)
	assert.JSONEq(t, string(responseBody), string(body),
		"response should pass through when API ID does not match session access rights")
}

func TestMCPListFilterResponseHandler_HandleResponse_SSEContentType(t *testing.T) {
	h := buildMCPListFilterHandler("api-1", true)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{
		Method: mcp.MethodToolsList,
		ID:     1,
	})

	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Tools: user.AccessControlRules{Blocked: []string{".*"}},
				},
			},
		},
	}

	responseBody := makeToolsListResponse([]map[string]any{
		{"name": "tool_a"},
	}, "")

	// SSE Content-Type should cause handler to skip (SSE handled by hook instead).
	res := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream; charset=utf-8"}},
		Body:       io.NopCloser(bytes.NewReader(responseBody)),
	}

	err := h.HandleResponse(rw, res, req, session)
	require.NoError(t, err)

	body := readResponseBody(t, res)
	assert.JSONEq(t, string(responseBody), string(body),
		"SSE responses should pass through unmodified")
}

func TestMCPListFilterResponseHandler_HandleResponse_Non200Status(t *testing.T) {
	h := buildMCPListFilterHandler("api-1", true)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{
		Method: mcp.MethodToolsList,
		ID:     1,
	})

	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Tools: user.AccessControlRules{Blocked: []string{".*"}},
				},
			},
		},
	}

	// A 500 error with a JSON-RPC error body (no "result" key).
	errorBody := []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"internal error"}}`)
	res := &http.Response{
		StatusCode: http.StatusInternalServerError,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(errorBody)),
	}

	err := h.HandleResponse(rw, res, req, session)
	require.NoError(t, err)

	body := readResponseBody(t, res)
	assert.JSONEq(t, string(errorBody), string(body),
		"error responses should pass through unmodified")
}

func TestMCPListFilterResponseHandler_HandleResponse_BatchResponse(t *testing.T) {
	h := buildMCPListFilterHandler("api-1", true)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{
		Method: mcp.MethodToolsList,
		ID:     1,
	})

	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Tools: user.AccessControlRules{Blocked: []string{".*"}},
				},
			},
		},
	}

	// JSON-RPC batch response (top-level array) — should pass through without crashing.
	batchBody := []byte(`[{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"}]}},{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"b"}]}}]`)
	res := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(batchBody)),
	}

	err := h.HandleResponse(rw, res, req, session)
	require.NoError(t, err)

	body := readResponseBody(t, res)
	assert.Equal(t, batchBody, body,
		"batch responses should pass through unmodified (not crash)")
}

func TestMCPListFilterResponseHandler_HandleResponse_ItemsMissingNameField(t *testing.T) {
	h := buildMCPListFilterHandler("api-1", true)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{
		Method: mcp.MethodToolsList,
		ID:     1,
	})

	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Tools: user.AccessControlRules{
						Allowed: []string{"keep_tool"},
					},
				},
			},
		},
	}

	// One tool has a name, one doesn't — nameless should pass through (fail-open).
	tools := []map[string]any{
		{"name": "keep_tool", "description": "has name"},
		{"description": "no name field"},
		{"name": "block_tool", "description": "not in allowlist"},
	}
	res := makeHTTPResponse(makeToolsListResponse(tools, ""))
	err := h.HandleResponse(rw, res, req, session)
	require.NoError(t, err)

	body := readResponseBody(t, res)
	got := extractToolNames(t, body)
	assert.Equal(t, []string{"keep_tool"}, got, "only named+allowed tools should be in names")

	// But the nameless item should also be in the result (fail-open).
	var envelope mcp.JSONRPCResponse
	require.NoError(t, json.Unmarshal(body, &envelope))
	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(envelope.Result, &result))
	var items []json.RawMessage
	require.NoError(t, json.Unmarshal(result["tools"], &items))
	assert.Len(t, items, 2, "should include keep_tool + nameless item (fail-open)")
}

// generateTools creates n tools with names "tool_0", "tool_1", ..., "tool_{n-1}".
func generateTools(n int) []map[string]any {
	tools := make([]map[string]any, n)
	for i := 0; i < n; i++ {
		tools[i] = map[string]any{
			"name":        fmt.Sprintf("tool_%d", i),
			"description": fmt.Sprintf("Tool number %d", i),
		}
	}
	return tools
}

func benchmarkMCPListFilter(b *testing.B, numTools int, rules user.AccessControlRules) {
	b.Helper()
	h := buildMCPListFilterHandler("api-1", true)
	tools := generateTools(numTools)
	responseBody := makeToolsListResponse(tools, "")

	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Tools: rules,
				},
			},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{
			Method: mcp.MethodToolsList,
			ID:     1,
		})
		res := makeHTTPResponse(responseBody)

		_ = h.HandleResponse(rw, res, req, session) //nolint:errcheck
		// Drain body to avoid leaks.
		io.ReadAll(res.Body) //nolint:errcheck
	}
}

func BenchmarkMCPListFilter_100Tools(b *testing.B) {
	allowed := make([]string, 10)
	for i := 0; i < 10; i++ {
		allowed[i] = fmt.Sprintf("tool_%d", i)
	}
	benchmarkMCPListFilter(b, 100, user.AccessControlRules{
		Allowed: allowed,
	})
}

func BenchmarkMCPListFilter_1000Tools(b *testing.B) {
	allowed := make([]string, 10)
	for i := 0; i < 10; i++ {
		allowed[i] = fmt.Sprintf("tool_%d", i)
	}
	benchmarkMCPListFilter(b, 1000, user.AccessControlRules{
		Allowed: allowed,
	})
}

func BenchmarkMCPListFilter_100Tools_Regex(b *testing.B) {
	benchmarkMCPListFilter(b, 100, user.AccessControlRules{
		Allowed: []string{"tool_[0-9]", "tool_1[0-9]"},
	})
}

func BenchmarkMCPListFilter_1000Tools_Regex(b *testing.B) {
	benchmarkMCPListFilter(b, 1000, user.AccessControlRules{
		Allowed: []string{"tool_[0-9]", "tool_1[0-9]"},
	})
}

func BenchmarkMCPListFilter_NoRules(b *testing.B) {
	benchmarkMCPListFilter(b, 1000, user.AccessControlRules{})
}
