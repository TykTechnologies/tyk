package gateway

import (
	"fmt"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/user"
)

// MCPAccessControlMiddleware enforces primitive-level access control for MCP APIs
// using mcp_access_rights from the session's access definition.
//
// MCP-specific: activates only for MCP APIs.
// Method-level access control is handled by JSONRPCAccessControlMiddleware.
type MCPAccessControlMiddleware struct {
	*BaseMiddleware
}

// Name returns the middleware name.
func (m *MCPAccessControlMiddleware) Name() string {
	return "MCPAccessControlMiddleware"
}

// EnabledForSpec returns true when the API is an MCP Proxy using JSON-RPC 2.0.
func (m *MCPAccessControlMiddleware) EnabledForSpec() bool {
	return m.Spec.IsMCP() && m.Spec.JsonRpcVersion == apidef.JsonRPC20
}

// ProcessRequest enforces MCP primitive allow/block rules.
// Skips when state.PrimitiveType is empty (non-primitive methods such as initialize, ping, tools/list).
//
//nolint:staticcheck
func (m *MCPAccessControlMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	state := httpctx.GetJSONRPCRoutingState(r)
	if state == nil || state.PrimitiveType == "" {
		return nil, http.StatusOK
	}

	session := ctxGetSession(r)
	if session == nil {
		return nil, http.StatusOK
	}

	accessDef, found := session.AccessRights[m.Spec.APIID]
	if !found || accessDef.MCPAccessRights.IsEmpty() {
		return nil, http.StatusOK
	}

	rules := rulesForPrimitiveType(accessDef.MCPAccessRights, state.PrimitiveType)
	if mcp.CheckAccessControlRules(rules, state.PrimitiveName) {
		writeJSONRPCAccessDenied(w, r,
			fmt.Sprintf("%s '%s' is not available", state.PrimitiveType, state.PrimitiveName))
		return nil, middleware.StatusRespond
	}

	return nil, http.StatusOK
}

// rulesForPrimitiveType returns the AccessControlRules for the given MCP primitive type.
// Returns an empty rules struct for unknown types (no access restriction applied).
func rulesForPrimitiveType(ar user.MCPAccessRights, primType string) user.AccessControlRules {
	switch primType {
	case mcp.PrimitiveTypeTool:
		return ar.Tools
	case mcp.PrimitiveTypeResource:
		return ar.Resources
	case mcp.PrimitiveTypePrompt:
		return ar.Prompts
	default:
		return user.AccessControlRules{}
	}
}
