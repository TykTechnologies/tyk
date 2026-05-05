package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/internal/httpctx"
	mcpproxy "github.com/TykTechnologies/tyk/internal/mcp/proxy"
	"github.com/TykTechnologies/tyk/user"
)

// MCPCallerAuthMiddleware establishes channel-trust on a loopback source
// when the call arrived in-process from a registered MCP Proxy.
//
// Insertion-position invariant (RFC §11): this middleware MUST be inserted
// on the source chain BEFORE `mwPreFuncs` (api_loader.go ~line 327,
// immediately after JSONRPCMiddleware / VersionCheck / CORSMiddleware).
// Earlier-than-pre-funcs placement is load-bearing — operator-configured
// pre-auth plugins could otherwise mutate the request or wipe the
// IsSelfLooping flag before trust is established. Phase B3 only builds
// the middleware; Phase C1 owns the chain-insertion patch in api_loader.go.
//
// When the channel-trust check passes, the middleware sets a synthetic
// user.SessionState on the request and flags downstream auth middlewares
// to short-circuit via httpctx.SetSkipAuth (the helper introduced in
// Phase B4 is what actually honours the flag — until B4 lands the flag is
// set but ignored, which is safe: the synthetic session is benign metadata
// when no skip-aware auth MW exists yet).
type MCPCallerAuthMiddleware struct {
	*BaseMiddleware
}

// Name returns the chain-log identifier for this middleware. The string
// is also referenced by RFC §15.2's insertion-position test plan.
func (m *MCPCallerAuthMiddleware) Name() string {
	return "MCPCallerAuth"
}

// EnabledForSpec activates the middleware when this APIDef is a loopback
// source that has opted in to MCP-Proxy callers via Server.AcceptMCPLoopCallers.
// The flag is the load-bearing toggle from RFC §7 / §11; sources that
// haven't opted in run their normal auth uniformly for all callers.
func (m *MCPCallerAuthMiddleware) EnabledForSpec() bool {
	if m == nil || m.Spec == nil {
		return false
	}
	ext := m.Spec.OAS.GetTykExtension()
	if ext == nil {
		return false
	}
	return ext.Server.AcceptMCPLoopCallers
}

// callerHasMCPProxyExtension returns true when the calling APISpec
// (resolved from the request context via httpctx.GetCallingSpec, then
// looked up in the gateway's apisByID map) carries the MCPProxy OAS
// extension on its Server block.
//
// Any failure mode (nil gateway, nil context, missing APIID, lookup miss,
// non-OAS APIDef, missing Tyk extension) yields false so that the §11
// decision tree can fail closed at the callerHasMCPProxyExt branch.
func (m *MCPCallerAuthMiddleware) callerHasMCPProxyExtension(r *http.Request) bool {
	if m == nil || m.Gw == nil {
		return false
	}
	callingSpec := httpctx.GetCallingSpec(r)
	if callingSpec == nil || callingSpec.APIID == "" {
		return false
	}

	m.Gw.apisMu.RLock()
	caller, ok := m.Gw.apisByID[callingSpec.APIID]
	m.Gw.apisMu.RUnlock()
	if !ok || caller == nil {
		// apisHandlesByID reload race or cross-tenant lookup miss —
		// RFC §11 explicitly fails closed here.
		return false
	}
	if !caller.IsOAS {
		// The MCPProxy extension lives only on OAS APIDefs; a
		// classic-only caller cannot hold it.
		return false
	}
	ext := caller.OAS.GetTykExtension()
	if ext == nil {
		return false
	}
	return ext.Server.MCPProxy != nil
}

// buildCallerAuth materialises a per-request CallerAuth snapshot from the
// source APISpec's OAS extension. We snapshot per-request rather than
// caching on the middleware struct because Server.MCPProxies can change
// across reloads (Proxy create/delete rewrites the back-ref) and a stale
// allowed-set is the multi-tenant safety bug §11 exists to prevent.
func (m *MCPCallerAuthMiddleware) buildCallerAuth() *mcpproxy.CallerAuth {
	ext := m.Spec.OAS.GetTykExtension()
	if ext == nil {
		return &mcpproxy.CallerAuth{}
	}
	allowed := make(map[string]struct{}, len(ext.Server.MCPProxies))
	for _, id := range ext.Server.MCPProxies {
		allowed[id] = struct{}{}
	}
	return &mcpproxy.CallerAuth{
		AcceptLoopCallers:  ext.Server.AcceptMCPLoopCallers,
		AllowedProxyAPIIDs: allowed,
	}
}

// applyTrust constructs and installs the synthetic session, then flags the
// request to skip downstream auth. Split out of ProcessRequest so the
// trust-application path is unit-testable in isolation.
//
// The synthetic session shape is RFC §11 verbatim:
//
//	KeyID:    "mcp:" + caller_apiid + ":" + agent_id
//	Alias:    "mcp:" + caller_apiid
//	MetaData: per-agent dimensions for rate-limit / analytics scoping.
//
// The metadata fields are sourced from X-Tyk-MCP-Context, which is
// metadata-not-trust per §8.4: a buggy or compromised Proxy can spoof
// agent_id and the worst that happens is wrong rate-limit attribution.
// Authoritative identity ("MCP traffic from caller_apiid") comes from the
// channel, not the header.
func (m *MCPCallerAuthMiddleware) applyTrust(r *http.Request, callerAPIID string) *http.Request {
	ctxHeader := mcpproxy.ParseContextHeader(r)

	synthetic := &user.SessionState{
		KeyID: "mcp:" + callerAPIID + ":" + ctxHeader.AgentID,
		Alias: "mcp:" + callerAPIID,
		MetaData: map[string]interface{}{
			"mcp_proxy_apiid": callerAPIID,
			"mcp_agent_id":    ctxHeader.AgentID,
			"mcp_tool_name":   ctxHeader.ToolName,
			"mcp_request_id":  ctxHeader.RequestID,
		},
	}

	// ctxSetSession verified at ctx/ctx.go:80 — (r, s, scheduleUpdate, hashKey).
	// scheduleUpdate=false: synthetic session has no persistent backing,
	//   so a Touch() write would be wasted I/O.
	// hashKey=false: KeyID is not a real bearer secret, so storing its
	//   hash form provides no anti-leak benefit and just costs cycles.
	ctxSetSession(r, synthetic, false, false)

	// SetSkipAuth returns a new *http.Request because the underlying
	// context.WithValue chain is immutable. Callers MUST replace their
	// local r with the returned value, otherwise the flag is dropped
	// the moment Go's middleware harness re-reads r.
	return httpctx.SetSkipAuth(r)
}

// ProcessRequest runs the §11 decision tree and applies the resulting
// Decision. The returned (nil, http.StatusOK) on every path lets the
// chain proceed: NoOp defers to the source's normal auth, Trust hands off
// to a downstream auth MW that observes httpctx.IsAuthSkipped (the
// helper-as-first patch landing in Phase B4).
//
// This middleware never writes to w directly. Even on Trust we return
// StatusOK because the synthetic-session installation is a context-only
// side effect; the actual response is produced by the upstream proxy or
// (for inline-response MCP methods) by middlewares further along.
//
// nolint:staticcheck — the (error, int) return order is the gateway's
// middleware-interface convention; it's not the Go-stdlib (int, error)
// order linters assume.
//
//nolint:staticcheck
func (m *MCPCallerAuthMiddleware) ProcessRequest(_ http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if r == nil {
		return nil, http.StatusOK
	}

	auth := m.buildCallerAuth()
	hasExt := m.callerHasMCPProxyExtension(r)

	switch auth.Evaluate(r, hasExt) {
	case mcpproxy.DecisionTrust:
		// callingSpec is non-nil here: Evaluate already gated on it.
		callingSpec := httpctx.GetCallingSpec(r)
		newReq := m.applyTrust(r, callingSpec.APIID)
		// Replace the request in-place so the rest of the chain
		// observes the skip-auth context value. *r = *newReq is the
		// idiom Tyk uses for context mutation in similar
		// "request-context-was-rebuilt" middlewares.
		*r = *newReq
		return nil, http.StatusOK
	case mcpproxy.DecisionNoOp:
		fallthrough
	default:
		// Source's normal auth runs.
		return nil, http.StatusOK
	}
}
