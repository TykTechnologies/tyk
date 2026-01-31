package gateway

import (
	"net/http"
	"net/url"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/httpctx"
)

// MCPVEMContinuationMiddleware handles sequential VEM routing for MCP JSON-RPC requests.
// After each VEM stage completes its middleware chain, this middleware checks the routing
// state and either continues to the next VEM or allows the request to proceed to upstream.
type MCPVEMContinuationMiddleware struct {
	*BaseMiddleware
}

// Name returns the middleware name for logging and debugging.
func (m *MCPVEMContinuationMiddleware) Name() string {
	return "MCPVEMContinuationMiddleware"
}

// EnabledForSpec returns true if this middleware should run for the given API spec.
// Only enabled for MCP APIs with JSON-RPC 2.0.
func (m *MCPVEMContinuationMiddleware) EnabledForSpec() bool {
	return m.Spec.IsMCP() && m.Spec.JsonRpcVersion == apidef.JsonRPC20
}

// ProcessRequest handles VEM chain continuation logic.
// This is GENERIC routing - just follows the NextVEM chain, no protocol logic.
//
//nolint:staticcheck // ST1008: middleware interface requires (error, int) return order
func (m *MCPVEMContinuationMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	state := httpctx.GetJSONRPCRoutingState(r)
	if state == nil {
		// Not an MCP JSON-RPC request or routing not initialized
		return nil, http.StatusOK
	}

	// Check if we're at the listen path (initial request before any VEM routing)
	// If so, don't interfere - JSONRPCMiddleware already set the rewrite target to the first VEM
	if r.URL.Path == state.OriginalPath {
		return nil, http.StatusOK
	}

	// We're at a VEM path - record it as visited
	httpctx.RecordVEMVisit(state, r.URL.Path)

	// Check if routing is complete (NextVEM is empty)
	if httpctx.IsRoutingComplete(r) {
		// Restore original path for upstream proxy
		// VEM paths are virtual internal routes and should not be sent to upstream
		r.URL.Path = state.OriginalPath
		r.URL.RawQuery = "" // Clear internal routing query params
		// No more routing needed, allow upstream
		return nil, http.StatusOK
	}

	// Route to next VEM
	nextVEM := state.NextVEM
	state.NextVEM = "" // Clear it (protocol layer will set next one if needed)
	httpctx.SetJSONRPCRoutingState(r, state)

	// Internal redirect to next VEM
	// Note: We pass check_limits via query param, which will be read by DummyProxyHandler
	// to set the context value for the next middleware chain execution
	ctxSetURLRewriteTarget(r, &url.URL{
		Scheme:   "tyk",
		Host:     "self",
		Path:     nextVEM,
		RawQuery: "check_limits=true",
	})

	// Return StatusOK to allow chain to continue to DummyProxyHandler, which will handle the redirect
	return nil, http.StatusOK
}
