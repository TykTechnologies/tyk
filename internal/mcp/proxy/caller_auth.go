// Package proxy contains the source-side decision logic for the MCP-Proxy
// channel-trust handshake. The pure-Go pieces here intentionally have no
// dependency on the gateway package, so the §11 RFC decision tree can be
// unit-tested without spinning up an APISpec, a Gateway, or a chain.
//
// The gateway shell that drives this logic lives in
// gateway/mw_mcp_caller_auth.go and is the only place that resolves the
// calling APISpec, parses headers off the live request, and mutates the
// request context.
package proxy

import (
	"encoding/json"
	"net/http"

	"github.com/TykTechnologies/tyk/internal/httpctx"
)

// HeaderXTykMCPContext is the metadata header injected by an MCP Proxy on
// mode-(a) loop hops. RFC §8.4: header is metadata, NEVER a trust input.
const HeaderXTykMCPContext = "X-Tyk-MCP-Context"

// Decision is the outcome of CallerAuth.Evaluate. The middleware caller is
// responsible for applying the decision (setting the synthetic session,
// flagging skip-auth). Evaluate is side-effect-free.
type Decision int

const (
	// DecisionNoOp means the call is not a trusted MCP loop, or trust
	// could not be established. Source's normal auth must run. Per
	// RFC §11 this is the fail-closed default.
	DecisionNoOp Decision = iota

	// DecisionTrust means the call arrived in-process via tyk:// from a
	// caller that (a) carries the MCPProxy extension AND (b) is listed
	// in this source's MCPProxies back-ref. The caller should construct
	// a synthetic session and mark auth as skipped.
	DecisionTrust
)

// String returns a human-readable name for the Decision, used in logs.
func (d Decision) String() string {
	switch d {
	case DecisionNoOp:
		return "no-op"
	case DecisionTrust:
		return "trust"
	default:
		return "unknown"
	}
}

// CallerAuth is a snapshot of the source-side configuration needed to
// evaluate a single request. The struct is constructed per-request from
// the source APIDef so that snapshot semantics are explicit; reusing a
// long-lived CallerAuth across reloads would risk a stale AllowedProxyAPIIDs
// surviving a Proxy delete.
type CallerAuth struct {
	// AcceptLoopCallers mirrors the source's
	// Server.AcceptMCPLoopCallers OAS field. When false, Evaluate
	// always returns DecisionNoOp without consulting the request — the
	// fast path for the overwhelming majority of non-MCP-aware sources.
	AcceptLoopCallers bool

	// AllowedProxyAPIIDs is the set form of the source's
	// Server.MCPProxies back-ref. Set form (not slice) so per-request
	// containment is O(1); the back-ref is rewritten on Proxy CRUD, not
	// on every request, so the set materialisation cost is amortised.
	AllowedProxyAPIIDs map[string]struct{}
}

// Evaluate inspects the request context and configuration and returns a
// Decision. The function is intentionally side-effect-free: it does NOT
// mutate r, set context values, or write to w. The caller observes the
// returned Decision and applies its effects.
//
// callerHasMCPProxyExt is supplied by the caller (the gateway shell) after
// resolving the calling APISpec via gw.apisByID and reading the OAS Tyk
// extension. Splitting the lookup out of Evaluate keeps the pure logic
// testable in isolation and means any failure in the gateway's spec
// resolution can fail closed by passing false.
//
// Decision tree (RFC §11):
//
//  1. AcceptLoopCallers != true                                  -> NoOp
//  2. !httpctx.IsSelfLooping(r)                                  -> NoOp
//  3. httpctx.GetCallingSpec(r) == nil                           -> NoOp
//  4. !callerHasMCPProxyExt                                      -> NoOp
//  5. caller_apiid not in AllowedProxyAPIIDs                     -> NoOp
//  6. otherwise                                                   -> Trust
//
// All NoOp paths are equivalent: source's normal auth is expected to run
// after Evaluate returns. Trust means "the caller has been recognised as a
// registered MCP Proxy and the source-side back-ref agrees".
func (c *CallerAuth) Evaluate(r *http.Request, callerHasMCPProxyExt bool) Decision {
	if c == nil {
		// Defensive: a nil CallerAuth means the caller did not have a
		// configured source-side snapshot. Fail closed.
		return DecisionNoOp
	}
	if !c.AcceptLoopCallers {
		return DecisionNoOp
	}
	if r == nil {
		return DecisionNoOp
	}
	if !httpctx.IsSelfLooping(r) {
		return DecisionNoOp
	}
	callingSpec := httpctx.GetCallingSpec(r)
	if callingSpec == nil {
		// Lookup-failure equivalent: the loop dispatcher did not stash
		// a calling APIDef, or context plumbing was disrupted. Per
		// RFC §11 (and §16 step 7) we MUST fail closed here — never
		// trust-grant on an unknown caller.
		return DecisionNoOp
	}
	if !callerHasMCPProxyExt {
		// Caller is a regular APIDef; channel-trust does not apply.
		return DecisionNoOp
	}
	if _, ok := c.AllowedProxyAPIIDs[callingSpec.APIID]; !ok {
		// Multi-tenant safety: the caller carries the MCPProxy
		// extension but is NOT a registered Proxy for this source.
		// Without this check, any tenant could mint an APIDef with
		// the extension and bypass auth into any source whose flag
		// is on (RFC §16 attack table).
		return DecisionNoOp
	}
	return DecisionTrust
}

// ContextHeader is the parsed shape of X-Tyk-MCP-Context. It is metadata,
// not a trust input — see RFC §8.4. The middleware reads it only to
// populate per-agent rate-limit and analytics dimensions on the synthetic
// session; corrupt or absent values degrade observability but never elevate
// trust.
type ContextHeader struct {
	AgentID    string `json:"agent_id"`
	ProxyAPIID string `json:"proxy_apiid"`
	ToolName   string `json:"tool_name"`
	RequestID  string `json:"request_id"`
	// IssuedAt is a Unix-seconds timestamp matching the int64 emit shape
	// of mcpContextHeader.IssuedAt in handler.go. Storing as int64 keeps
	// the parse and emit sides symmetric; mismatched types here silently
	// dropped the field on inbound parses prior to Phase C.
	IssuedAt   int64  `json:"issued_at"`
}

// ParseContextHeader extracts and parses the X-Tyk-MCP-Context header from
// the request. The function is deliberately tolerant: a missing header,
// empty value, or malformed JSON yields the zero ContextHeader and no
// error. The header is never load-bearing for trust decisions, so a
// hard-failure path here would be a denial-of-service vector against the
// source for no security gain.
func ParseContextHeader(r *http.Request) ContextHeader {
	if r == nil {
		return ContextHeader{}
	}
	raw := r.Header.Get(HeaderXTykMCPContext)
	if raw == "" {
		return ContextHeader{}
	}
	var ch ContextHeader
	// Tolerate malformed JSON: discard the parse error. Callers see
	// the zero value, which downstream code (rate-limit bucket key,
	// analytics) handles uniformly with the "no header" case.
	_ = json.Unmarshal([]byte(raw), &ch)
	return ch
}
