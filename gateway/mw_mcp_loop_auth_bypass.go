package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp/pairing"
	"github.com/TykTechnologies/tyk/user"
)

// MCPLoopAuthBypass short-circuits REST-side authentication for requests
// that arrived from a paired MCP adapter via the `tyk://` loop primitive.
//
// Trust model (defence in depth, two independent gates):
//
//  1. Adapter middleware stamps a `MCPLoopTrust` descriptor on the
//     outgoing request before dispatching it back through the REST chain.
//     The flag is set by trusted in-process code; it never crosses a
//     network boundary.
//  2. This middleware re-checks the pairing index — pairing.Lookup —
//     and refuses to honour the descriptor unless the proxyAPIID it
//     names matches the proxy the gateway has admitted as the 1:1
//     caller for this REST API. A descriptor that was somehow forged
//     or replayed against an unpaired REST API returns 403.
//
// The middleware accepts a pairing.Lookup interface (instead of
// reaching into the Gateway struct) so unit tests can supply a fake.
// The gateway's *pairing.Index satisfies the interface in production.
type MCPLoopAuthBypass struct {
	*BaseMiddleware

	// Pairing is the lookup the middleware consults. If nil at chain
	// build time, ProcessRequest falls back to m.Gw.mcpPairing.
	Pairing pairing.Lookup
}

// Name returns the middleware name.
func (m *MCPLoopAuthBypass) Name() string {
	return "MCPLoopAuthBypass"
}

// EnabledForSpec returns true only on REST APIs that opted into MCP
// exposure. Non-MCP-exposed APIs do not need this middleware.
func (m *MCPLoopAuthBypass) EnabledForSpec() bool {
	if m.Spec == nil || m.Spec.APIDefinition == nil {
		return false
	}
	return m.Spec.IsMCPExposed()
}

// ProcessRequest reads the trust descriptor and either short-circuits
// auth, rejects a mismatched pairing, or falls through for normal REST
// clients.
//
//nolint:staticcheck // middleware interface requires (error, int) return
func (m *MCPLoopAuthBypass) ProcessRequest(_ http.ResponseWriter, r *http.Request, _ any) (error, int) {
	trust := httpctx.GetMCPLoopFromPairedProxy(r)
	if trust == nil {
		// Normal REST client — let regular auth chain run.
		return nil, http.StatusOK
	}

	lookup := m.Pairing
	if lookup == nil {
		lookup = m.Gw.mcpPairing
	}

	expectedProxy, paired := lookup.ProxyForREST(m.Spec.APIID)
	if !paired || expectedProxy != trust.ProxyAPIID {
		m.Logger().WithFields(map[string]interface{}{
			"rest_api_id":     m.Spec.APIID,
			"flag_proxy_id":   trust.ProxyAPIID,
			"flag_adapter_id": trust.AdapterAPIID,
			"expected_proxy":  expectedProxy,
			"is_paired":       paired,
		}).Warn("MCPLoopAuthBypass: trust descriptor pairing mismatch — rejecting")
		return errMCPLoopForgery, http.StatusForbidden
	}

	session := makeMCPLoopSession(trust)
	// Pass two trailing booleans so ctx.SetSession uses the explicit
	// hashKey rather than dereferencing config.Global() — keeps unit
	// tests free of global-config setup.
	ctx.SetSession(r, session, false, false, false)

	return nil, http.StatusOK
}

// errMCPLoopForgery is the canonical error returned when the trust
// descriptor does not match an admitted pairing.
var errMCPLoopForgery = mcpLoopForgeryError{}

type mcpLoopForgeryError struct{}

func (mcpLoopForgeryError) Error() string {
	return "MCP loop trust descriptor does not match an admitted paired proxy"
}

// makeMCPLoopSession returns an in-memory session marking the request
// as having been pre-authorised by the paired MCP proxy. Real session
// policy attachment is owned by the proxy's own auth chain; this stub
// only ensures REST-side middlewares observe a non-nil session.
func makeMCPLoopSession(trust *httpctx.MCPLoopTrust) *user.SessionState {
	s := user.NewSessionState()
	s.KeyID = "mcp-loop:" + trust.ProxyAPIID
	s.Alias = "mcp-loop-paired-proxy"
	if s.MetaData == nil {
		s.MetaData = map[string]interface{}{}
	}
	s.MetaData["mcp_proxy_api_id"] = trust.ProxyAPIID
	s.MetaData["mcp_adapter_api_id"] = trust.AdapterAPIID
	s.MetaData["mcp_rest_api_id"] = trust.RESTAPIID
	return s
}
