package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/user"
)

// buildJSONRPCACLMiddleware creates a JSONRPCAccessControlMiddleware for testing.
func buildJSONRPCACLMiddleware(apiID string, isMCP bool) *JSONRPCAccessControlMiddleware {
	proto := ""
	if isMCP {
		proto = apidef.AppProtocolMCP
	}
	return &JSONRPCAccessControlMiddleware{
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

func TestJSONRPCAccessControlMiddleware_EnabledForSpec(t *testing.T) {
	tests := []struct {
		name    string
		isMCP   bool
		enabled bool
	}{
		{"MCP API - enabled", true, true},
		{"non-MCP API - disabled", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := buildJSONRPCACLMiddleware("api-1", tt.isMCP)
			assert.Equal(t, tt.enabled, mw.EnabledForSpec())
		})
	}
}

func TestJSONRPCAccessControlMiddleware_NoState(t *testing.T) {
	mw := buildJSONRPCACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	// No routing state set — should pass through
	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestJSONRPCAccessControlMiddleware_NoSession(t *testing.T) {
	mw := buildJSONRPCACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	httpctx.SetJSONRPCRoutingState(r, &httpctx.JSONRPCRoutingState{Method: "tools/call"})
	// No session set — should pass through

	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestJSONRPCAccessControlMiddleware_EmptyAccessRights(t *testing.T) {
	mw := buildJSONRPCACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	httpctx.SetJSONRPCRoutingState(r, &httpctx.JSONRPCRoutingState{Method: "tools/call"})
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {APIID: "api-1"}, // no JSONRPCMethodsAccessRights
		},
	}
	setSessionForTest(r, session)

	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestJSONRPCAccessControlMiddleware_AllowedMethod_Passes(t *testing.T) {
	mw := buildJSONRPCACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	httpctx.SetJSONRPCRoutingState(r, &httpctx.JSONRPCRoutingState{Method: "tools/call"})
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				JSONRPCMethodsAccessRights: user.AccessControlRules{
					Allowed: []string{"tools/call", "tools/list"},
				},
			},
		},
	}
	setSessionForTest(r, session)

	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestJSONRPCAccessControlMiddleware_NotInAllowedList_Blocked(t *testing.T) {
	mw := buildJSONRPCACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	httpctx.SetJSONRPCRoutingState(r, &httpctx.JSONRPCRoutingState{
		Method: "tools/list",
		ID:     1,
	})
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				JSONRPCMethodsAccessRights: user.AccessControlRules{
					Allowed: []string{"resources/.*"},
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

func TestJSONRPCAccessControlMiddleware_BlockedMethod_Denied(t *testing.T) {
	mw := buildJSONRPCACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	httpctx.SetJSONRPCRoutingState(r, &httpctx.JSONRPCRoutingState{
		Method: "tools/list",
		ID:     2,
	})
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				JSONRPCMethodsAccessRights: user.AccessControlRules{
					Blocked: []string{"tools/list"},
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

func TestJSONRPCAccessControlMiddleware_BlockedRegex_Denied(t *testing.T) {
	mw := buildJSONRPCACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	httpctx.SetJSONRPCRoutingState(r, &httpctx.JSONRPCRoutingState{Method: "tools/call"})
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				JSONRPCMethodsAccessRights: user.AccessControlRules{
					Blocked: []string{"tools/.*"},
				},
			},
		},
	}
	setSessionForTest(r, session)

	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, code)
}

func TestJSONRPCAccessControlMiddleware_AllowedRegex_Passes(t *testing.T) {
	mw := buildJSONRPCACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	httpctx.SetJSONRPCRoutingState(r, &httpctx.JSONRPCRoutingState{Method: "resources/read"})
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				JSONRPCMethodsAccessRights: user.AccessControlRules{
					Allowed: []string{"resources/.*"},
				},
			},
		},
	}
	setSessionForTest(r, session)

	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestJSONRPCAccessControlMiddleware_APINotInAccessRights(t *testing.T) {
	mw := buildJSONRPCACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	httpctx.SetJSONRPCRoutingState(r, &httpctx.JSONRPCRoutingState{Method: "tools/call"})
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"other-api": {APIID: "other-api"}, // different API
		},
	}
	setSessionForTest(r, session)

	// API not in access rights — pass through
	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
}

// TestJSONRPCAccessControlMiddleware_ResponseBody verifies the JSON-RPC error response format.
func TestJSONRPCAccessControlMiddleware_ResponseBody(t *testing.T) {
	mw := buildJSONRPCACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	httpctx.SetJSONRPCRoutingState(r, &httpctx.JSONRPCRoutingState{
		Method: "tools/list",
		ID:     99,
	})
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				JSONRPCMethodsAccessRights: user.AccessControlRules{
					Blocked: []string{"tools/list"},
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
	assert.Contains(t, body, "tools/list")
	assert.Contains(t, body, "not available")
}

func TestJSONRPCAccessControlMiddleware_StatusOkAndIgnore_Skips(t *testing.T) {
	mw := buildJSONRPCACLMiddleware("api-1", true)
	r := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()

	// Set up a blocked method that would normally be denied
	httpctx.SetJSONRPCRoutingState(r, &httpctx.JSONRPCRoutingState{
		Method: "tools/list",
		ID:     1,
	})
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID: "api-1",
				JSONRPCMethodsAccessRights: user.AccessControlRules{
					Blocked: []string{"tools/list"},
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
