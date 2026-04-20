package gateway

import (
	"fmt"
	"net/http"

	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/middleware"
)

// JSONRPCAccessControlMiddleware enforces method-level access control for JSON-RPC APIs
// using json_rpc_methods_access_rights from the session's access definition.
//
// Scoped to MCP APIs only — registered in the chain only when spec.IsMCP() is true (Step 8.2).
// If method-level access control is later needed for other JSON-RPC protocols (A2A, etc.),
// the chain guard in api_loader.go can be widened to if spec.JsonRpcVersion == apidef.JsonRPC20.
type JSONRPCAccessControlMiddleware struct {
	*BaseMiddleware
}

// Name returns the middleware name.
func (m *JSONRPCAccessControlMiddleware) Name() string {
	return "JSONRPCAccessControlMiddleware"
}

// EnabledForSpec returns true when the API is an MCP Proxy.
// Defence-in-depth: the if spec.IsMCP() guard in api_loader.go is the primary guard;
// this is the secondary safety net consistent with the standard Tyk middleware pattern.
func (m *JSONRPCAccessControlMiddleware) EnabledForSpec() bool {
	return m.Spec.IsMCP()
}

// ProcessRequest enforces JSON-RPC method allow/block rules.
//
//nolint:staticcheck
func (m *JSONRPCAccessControlMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	state := httpctx.GetJSONRPCRoutingState(r)
	if state == nil {
		return nil, http.StatusOK
	}

	session := ctxGetSession(r)
	if session == nil {
		return nil, http.StatusOK
	}

	accessDef, found := session.AccessRights[m.Spec.APIID]
	if !found || accessDef.JSONRPCMethodsAccessRights.IsEmpty() {
		return nil, http.StatusOK
	}

	if mcp.CheckAccessControlRules(accessDef.JSONRPCMethodsAccessRights, state.Method) {
		writeJSONRPCAccessDenied(w, r, fmt.Sprintf("method '%s' is not available", state.Method))
		return nil, middleware.StatusRespond
	}

	return nil, http.StatusOK
}
