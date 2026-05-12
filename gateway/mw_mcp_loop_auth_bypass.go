package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/httpctx"
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
//  2. This middleware re-checks the pairing index — gw.mcpPairing —
//     and refuses to honour the descriptor unless the proxyAPIID it
//     names matches the proxy the gateway has admitted as the 1:1 caller
//     for this REST API. A descriptor that was somehow forged or
//     replayed against an unpaired REST API returns 403.
//
// On a valid match, the middleware installs an in-memory session
// derived from the proxy's identity. Subsequent auth middlewares
// (AuthKey, JWT, etc.) see a session already in context — they remain
// untouched and run normally for direct REST clients (no flag → no
// bypass).
type MCPLoopAuthBypass struct {
	*BaseMiddleware
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
	return m.Spec.APIDefinition.IsMCPExposed()
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

	// Defence-in-depth: even if a flag was somehow forged, the pairing
	// index disagrees unless an operator-admitted MCP proxy targets this
	// REST API.
	m.Gw.apisMu.RLock()
	expectedProxy, paired := m.Gw.mcpPairing[m.Spec.APIID]
	m.Gw.apisMu.RUnlock()

	if !paired || expectedProxy != trust.ProxyAPIID {
		m.Logger().WithFields(map[string]interface{}{
			"rest_api_id":      m.Spec.APIID,
			"flag_proxy_id":    trust.ProxyAPIID,
			"flag_adapter_id":  trust.AdapterAPIID,
			"expected_proxy":   expectedProxy,
			"is_paired":        paired,
		}).Warn("MCPLoopAuthBypass: trust descriptor pairing mismatch — rejecting")
		return errMCPLoopForgery, http.StatusForbidden
	}

	// Mint a minimal in-memory session that represents the paired
	// proxy. Other middlewares see a session in context and skip their
	// credential checks. Quota/rate-limit middlewares apply the
	// configured limits keyed on this session.
	session := makeMCPLoopSession(trust)
	// Pass two trailing booleans so ctx.SetSession uses the explicit
	// hashKey value rather than dereferencing config.Global() — keeps
	// unit tests free of global-config setup. Production callers (the
	// HashKeys-aware path) get the same effective result.
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
	// Mark the session metadata so any audit log emitted by the REST
	// chain can attribute the request back to the proxy and adapter.
	if s.MetaData == nil {
		s.MetaData = map[string]interface{}{}
	}
	s.MetaData["mcp_proxy_api_id"] = trust.ProxyAPIID
	s.MetaData["mcp_adapter_api_id"] = trust.AdapterAPIID
	s.MetaData["mcp_rest_api_id"] = trust.RESTAPIID
	return s
}
