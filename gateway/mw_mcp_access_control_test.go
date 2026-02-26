package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/user"
)

// buildMCPACLMiddleware creates a MCPAccessControlMiddleware for testing.
func buildMCPACLMiddleware(apiID string, isMCP bool) *MCPAccessControlMiddleware {
	proto := ""
	if isMCP {
		proto = apidef.AppProtocolMCP
	}
	return &MCPAccessControlMiddleware{
		BaseMiddleware: &BaseMiddleware{
			Spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					APIID:               apiID,
					ApplicationProtocol: proto,
					JsonRpcVersion:      apidef.JsonRPC20,
				},
			},
		},
	}
}

// primitiveState returns a routing state with the given primitive type and name.
func primitiveState(primType, primName string) *httpctx.JSONRPCRoutingState {
	return &httpctx.JSONRPCRoutingState{
		Method:        "tools/call",
		PrimitiveType: primType,
		PrimitiveName: primName,
		ID:            1,
	}
}

func TestMCPAccessControlMiddleware_EnabledForSpec(t *testing.T) {
	tests := []struct {
		name       string
		isMCP      bool
		jsonrpcVer string
		enabled    bool
	}{
		{"MCP + JSON-RPC 2.0 - enabled", true, apidef.JsonRPC20, true},
		{"non-MCP - disabled", false, apidef.JsonRPC20, false},
		{"MCP + no JSON-RPC - disabled", true, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proto := ""
			if tt.isMCP {
				proto = apidef.AppProtocolMCP
			}
			mw := &MCPAccessControlMiddleware{
				BaseMiddleware: &BaseMiddleware{
					Spec: &APISpec{
						APIDefinition: &apidef.APIDefinition{
							APIID:               "api-1",
							ApplicationProtocol: proto,
							JsonRpcVersion:      tt.jsonrpcVer,
						},
					},
				},
			}
			assert.Equal(t, tt.enabled, mw.EnabledForSpec())
		})
	}
}

func TestMCPAccessControlMiddleware_NoState(t *testing.T) {
	mw := buildMCPACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestMCPAccessControlMiddleware_NonPrimitiveMethod_Skips(t *testing.T) {
	mw := buildMCPACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	// PrimitiveType is "" for non-primitive methods (initialize, ping, tools/list, etc.)
	httpctx.SetJSONRPCRoutingState(r, &httpctx.JSONRPCRoutingState{
		Method:        "tools/list",
		PrimitiveType: "",
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
	setSessionForTest(r, session)

	// Should pass — PrimitiveType is empty
	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestMCPAccessControlMiddleware_EmptyMCPAccessRights_Passes(t *testing.T) {
	mw := buildMCPACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	httpctx.SetJSONRPCRoutingState(r, primitiveState(mcp.PrimitiveTypeTool, "get_weather"))
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {APIID: "api-1"}, // no MCPAccessRights
		},
	}
	setSessionForTest(r, session)

	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestMCPAccessControlMiddleware_AllowedTool_Passes(t *testing.T) {
	mw := buildMCPACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	httpctx.SetJSONRPCRoutingState(r, primitiveState(mcp.PrimitiveTypeTool, "get_weather"))
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Tools: user.AccessControlRules{Allowed: []string{"get_weather", "get_forecast"}},
				},
			},
		},
	}
	setSessionForTest(r, session)

	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestMCPAccessControlMiddleware_ToolNotInAllowList_Denied(t *testing.T) {
	mw := buildMCPACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	httpctx.SetJSONRPCRoutingState(r, primitiveState(mcp.PrimitiveTypeTool, "delete_all"))
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Tools: user.AccessControlRules{Allowed: []string{"get_weather"}},
				},
			},
		},
	}
	setSessionForTest(r, session)

	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, code)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestMCPAccessControlMiddleware_BlockedTool_Denied(t *testing.T) {
	mw := buildMCPACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	httpctx.SetJSONRPCRoutingState(r, primitiveState(mcp.PrimitiveTypeTool, "delete_alert"))
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Tools: user.AccessControlRules{Blocked: []string{"delete_alert", "reset_system"}},
				},
			},
		},
	}
	setSessionForTest(r, session)

	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, code)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestMCPAccessControlMiddleware_BlockedToolRegex_Denied(t *testing.T) {
	mw := buildMCPACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	httpctx.SetJSONRPCRoutingState(r, primitiveState(mcp.PrimitiveTypeTool, "delete_user"))
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Tools: user.AccessControlRules{Blocked: []string{"delete_.*"}},
				},
			},
		},
	}
	setSessionForTest(r, session)

	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, code)
}

func TestMCPAccessControlMiddleware_BlockedToolRegex_AllowedOther(t *testing.T) {
	mw := buildMCPACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	httpctx.SetJSONRPCRoutingState(r, primitiveState(mcp.PrimitiveTypeTool, "get_user"))
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Tools: user.AccessControlRules{Blocked: []string{"delete_.*"}},
				},
			},
		},
	}
	setSessionForTest(r, session)

	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestMCPAccessControlMiddleware_DenyTakesPrecedenceOverAllow(t *testing.T) {
	mw := buildMCPACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	// reset_system is in both allowed and blocked — blocked wins
	httpctx.SetJSONRPCRoutingState(r, primitiveState(mcp.PrimitiveTypeTool, "reset_system"))
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Tools: user.AccessControlRules{
						Blocked: []string{"reset_system"},
						Allowed: []string{"reset_system"},
					},
				},
			},
		},
	}
	setSessionForTest(r, session)

	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, code)
}

func TestMCPAccessControlMiddleware_Resource_AllowedURI(t *testing.T) {
	mw := buildMCPACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	httpctx.SetJSONRPCRoutingState(r, primitiveState(mcp.PrimitiveTypeResource, "file:///public/readme.md"))
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Resources: user.AccessControlRules{Allowed: []string{"file:///public/.*"}},
				},
			},
		},
	}
	setSessionForTest(r, session)

	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestMCPAccessControlMiddleware_Resource_DeniedURI(t *testing.T) {
	mw := buildMCPACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	httpctx.SetJSONRPCRoutingState(r, primitiveState(mcp.PrimitiveTypeResource, "file:///secret/keys.txt"))
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Resources: user.AccessControlRules{Allowed: []string{"file:///public/.*"}},
				},
			},
		},
	}
	setSessionForTest(r, session)

	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, code)
}

func TestMCPAccessControlMiddleware_Prompt_BlockedRegex(t *testing.T) {
	mw := buildMCPACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	httpctx.SetJSONRPCRoutingState(r, primitiveState(mcp.PrimitiveTypePrompt, "admin_setup"))
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Prompts: user.AccessControlRules{Blocked: []string{"admin_.*"}},
				},
			},
		},
	}
	setSessionForTest(r, session)

	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, code)
}

func TestMCPAccessControlMiddleware_Prompt_AllowedOther(t *testing.T) {
	mw := buildMCPACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	httpctx.SetJSONRPCRoutingState(r, primitiveState(mcp.PrimitiveTypePrompt, "user_greeting"))
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Prompts: user.AccessControlRules{Blocked: []string{"admin_.*"}},
				},
			},
		},
	}
	setSessionForTest(r, session)

	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestMCPAccessControlMiddleware_ToolRuleDoesNotAffectResource(t *testing.T) {
	mw := buildMCPACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	// Tool is blocked, but we're accessing a resource — should pass
	httpctx.SetJSONRPCRoutingState(r, primitiveState(mcp.PrimitiveTypeResource, "file:///data.json"))
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Tools: user.AccessControlRules{Blocked: []string{".*"}}, // blocks all tools
					// no resource rules
				},
			},
		},
	}
	setSessionForTest(r, session)

	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestRulesForPrimitiveType(t *testing.T) {
	ar := user.MCPAccessRights{
		Tools:     user.AccessControlRules{Allowed: []string{"tool-a"}},
		Resources: user.AccessControlRules{Blocked: []string{"secret-.*"}},
		Prompts:   user.AccessControlRules{Allowed: []string{"safe_prompt"}},
	}

	tests := []struct {
		primType string
		expected user.AccessControlRules
	}{
		{mcp.PrimitiveTypeTool, ar.Tools},
		{mcp.PrimitiveTypeResource, ar.Resources},
		{mcp.PrimitiveTypePrompt, ar.Prompts},
		{"unknown", user.AccessControlRules{}},
		{"", user.AccessControlRules{}},
	}

	for _, tt := range tests {
		t.Run(tt.primType, func(t *testing.T) {
			got := rulesForPrimitiveType(ar, tt.primType)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestMCPAccessControlMiddleware_ResponseBody verifies JSON-RPC error shape.
func TestMCPAccessControlMiddleware_ResponseBody(t *testing.T) {
	mw := buildMCPACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	httpctx.SetJSONRPCRoutingState(r, primitiveState(mcp.PrimitiveTypeTool, "dangerous_tool"))
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Tools: user.AccessControlRules{Blocked: []string{"dangerous_.*"}},
				},
			},
		},
	}
	setSessionForTest(r, session)

	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, code)

	require.Equal(t, http.StatusForbidden, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "jsonrpc")
	assert.Contains(t, body, "dangerous_tool")
	assert.Contains(t, body, "not available")
}

func TestMCPAccessControlMiddleware_StatusOkAndIgnore_Skips(t *testing.T) {
	mw := buildMCPACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	// Set up a blocked tool that would normally be denied
	httpctx.SetJSONRPCRoutingState(r, primitiveState(mcp.PrimitiveTypeTool, "dangerous_tool"))
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				MCPAccessRights: user.MCPAccessRights{
					Tools: user.AccessControlRules{Blocked: []string{"dangerous_.*"}},
				},
			},
		},
	}
	setSessionForTest(r, session)

	// Mark request as ignored endpoint — middleware must skip
	ctxSetRequestStatus(r, StatusOkAndIgnore)

	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
}
