package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/internal/httpctx"
)

// MCPLoopAuthRestore restores normal request-status handling after the
// REST-side auth and session quota band has skipped a validated MCP loop.
type MCPLoopAuthRestore struct {
	*BaseMiddleware
}

// Name returns the middleware name.
func (m *MCPLoopAuthRestore) Name() string {
	return "MCPLoopAuthRestore"
}

// EnabledForSpec returns true on non-MCP, non-synthetic APIs where
// MCPLoopAuthBypass may have installed a temporary bypass status.
func (m *MCPLoopAuthRestore) EnabledForSpec() bool {
	if m.Spec == nil || m.Spec.APIDefinition == nil {
		return false
	}
	return !m.Spec.IsMCP() && !m.Spec.IsSyntheticMCPAdapter
}

// ProcessRequest restores StatusOk so downstream/global REST middlewares do not
// inherit the temporary auth-bypass StatusOkAndIgnore marker.
//
//nolint:staticcheck // middleware interface requires (error, int) return
func (m *MCPLoopAuthRestore) ProcessRequest(_ http.ResponseWriter, r *http.Request, _ any) (error, int) {
	if httpctx.IsMCPLoopPreAuthorized(r) {
		ctxSetRequestStatus(r, StatusOk)
	}
	return nil, http.StatusOK
}
