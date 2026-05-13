package gateway

import (
	"encoding/json"
	"net/http"

	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	mcpadapter "github.com/TykTechnologies/tyk/internal/mcp/adapter"
)

// handleAdapterInline answers initialize / ping / tools/list inline for
// a synthetic adapter spec. Returns true if the method was handled and
// the JSON-RPC envelope has been written to w; the caller must then
// return middleware.StatusRespond.
//
// All envelope assembly lives in internal/mcp/adapter — this method
// is a thin chain-aware shim that translates between the chain's
// JSONRPCRequest type and the package's primitives.
func (m *JSONRPCMiddleware) handleAdapterInline(w http.ResponseWriter, _ *http.Request, rpcReq *JSONRPCRequest) bool {
	if m.Spec == nil || !m.Spec.IsSyntheticMCPAdapter {
		return false
	}

	switch rpcReq.Method {
	case mcpadapter.MethodInitialize:
		mcpadapter.WriteJSON(w, mcpadapter.JSONRPCResult(rpcReq.ID, mcpadapter.InitializeResult(m.Spec.Name)))
		return true
	case mcpadapter.MethodPing:
		mcpadapter.WriteJSON(w, mcpadapter.JSONRPCResult(rpcReq.ID, map[string]any{}))
		return true
	case mcp.MethodToolsList:
		mcpadapter.WriteJSON(w, mcpadapter.JSONRPCResult(rpcReq.ID, mcpadapter.ToolsListResult(m.Spec.DerivedTools)))
		return true
	}
	return false
}

// handleAdapterToolsCall translates a `tools/call` envelope into an
// HTTP request against the paired REST API, stamps the trust descriptor
// so MCPLoopAuthBypass on the REST side can short-circuit auth, and
// dispatches via the REST API's handler.
//
// Returns true if the call was handled (success or error) and the
// caller must return middleware.StatusRespond.
func (gw *Gateway) handleAdapterToolsCall(
	w http.ResponseWriter,
	r *http.Request,
	spec *APISpec,
	rpcReq *JSONRPCRequest,
) bool {
	if spec == nil || !spec.IsSyntheticMCPAdapter {
		return false
	}
	if rpcReq.Method != mcp.MethodToolsCall {
		return false
	}

	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if len(rpcReq.Params) > 0 {
		if err := json.Unmarshal(rpcReq.Params, &params); err != nil {
			mcpadapter.WriteJSON(w, mcpadapter.JSONRPCError(rpcReq.ID, mcpadapter.JSONRPCInvalidParams, "invalid tools/call params: "+err.Error()))
			return true
		}
	}
	if params.Name == "" {
		mcpadapter.WriteJSON(w, mcpadapter.JSONRPCError(rpcReq.ID, mcpadapter.JSONRPCInvalidParams, "tools/call requires a tool name"))
		return true
	}

	tool := mcpadapter.FindTool(spec.DerivedTools, params.Name)
	if tool == nil {
		mcpadapter.WriteJSON(w, mcpadapter.JSONRPCError(rpcReq.ID, mcpadapter.JSONRPCMethodNotFound, "unknown tool: "+params.Name))
		return true
	}

	upstreamReq, err := mcpadapter.BuildUpstreamRequest(r, tool, spec.SourceRESTAPIID, params.Arguments)
	if err != nil {
		mcpadapter.WriteJSON(w, mcpadapter.JSONRPCError(rpcReq.ID, mcpadapter.JSONRPCInternalError, err.Error()))
		return true
	}

	proxyAPIID, paired := gw.mcpPairing.ProxyForREST(spec.SourceRESTAPIID)
	if !paired {
		mcpadapter.WriteJSON(w, mcpadapter.JSONRPCError(rpcReq.ID, mcpadapter.JSONRPCInternalError, "no MCP proxy paired with this REST API"))
		return true
	}

	httpctx.SetMCPLoopFromPairedProxy(upstreamReq, &httpctx.MCPLoopTrust{
		ProxyAPIID:   proxyAPIID,
		RESTAPIID:    spec.SourceRESTAPIID,
		AdapterAPIID: spec.APIID,
	})

	handler, _, ok := gw.findInternalHttpHandlerByNameOrID(spec.SourceRESTAPIID)
	if !ok {
		mcpadapter.WriteJSON(w, mcpadapter.JSONRPCError(rpcReq.ID, mcpadapter.JSONRPCInternalError, "paired REST API handler not found"))
		return true
	}

	rec := mcpadapter.NewRecorder()
	handler.ServeHTTP(rec, upstreamReq)

	mcpadapter.WriteJSON(w, mcpadapter.JSONRPCResult(rpcReq.ID, mcpadapter.ToolResultEnvelope(rec)))
	return true
}
