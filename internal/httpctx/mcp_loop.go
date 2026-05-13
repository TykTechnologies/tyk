package httpctx

import (
	"context"
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
)

// MCPLoopTrust is the descriptor an MCP adapter middleware stamps on a
// request before dispatching it back through the paired REST API via the
// `tyk://` loop primitive.
//
// MCPLoopAuthBypass reads this descriptor on the REST side and uses it
// to skip credential validation — but only after cross-checking
// gw.mcpPairing[RESTAPIID] == ProxyAPIID.
type MCPLoopTrust struct {
	// ProxyAPIID is the operator-managed MCP proxy APIID that
	// authenticated the agent. MCPLoopAuthBypass requires this to match
	// gw.mcpPairing[RESTAPIID] before short-circuiting auth.
	ProxyAPIID string
	// RESTAPIID is the source REST APIID the adapter is looping into.
	// Carried so the bypass middleware can sanity-check that the spec
	// it is running on matches what the adapter intended.
	RESTAPIID string
	// AdapterAPIID is the synthetic adapter that emitted the loop.
	// Recorded for diagnostics.
	AdapterAPIID string
}

var mcpLoopTrustValue = NewValue[*MCPLoopTrust](ctx.MCPLoopFromPairedProxy)

type mcpLoopPreAuthorizedKey struct{}

var mcpLoopPreAuthorizedValue = NewValue[bool](mcpLoopPreAuthorizedKey{})

type mcpProxyCallerAPIIDKey struct{}

var mcpProxyCallerAPIIDValue = NewValue[string](mcpProxyCallerAPIIDKey{})

// SetMCPLoopFromPairedProxy stamps the trust descriptor on a request
// that an adapter middleware is about to dispatch through the loop
// primitive. Pass nil to clear.
func SetMCPLoopFromPairedProxy(r *http.Request, trust *MCPLoopTrust) {
	mcpLoopTrustValue.Set(r, trust)
}

// GetMCPLoopFromPairedProxy returns the trust descriptor stamped on the
// request, or nil if the request did not arrive via an MCP adapter
// loop.
func GetMCPLoopFromPairedProxy(r *http.Request) *MCPLoopTrust {
	return mcpLoopTrustValue.Get(r)
}

// SetMCPLoopPreAuthorized marks a request whose in-process MCP loop trust
// descriptor was validated by gateway middleware.
func SetMCPLoopPreAuthorized(r *http.Request, preAuthorized bool) {
	mcpLoopPreAuthorizedValue.Set(r, preAuthorized)
}

// IsMCPLoopPreAuthorized reports whether the MCP loop trust descriptor on the
// request has been validated by gateway middleware.
func IsMCPLoopPreAuthorized(r *http.Request) bool {
	return mcpLoopPreAuthorizedValue.Get(r)
}

// SetMCPProxyCallerAPIID stores the proxy APIID that internally called a
// synthetic REST-as-MCP adapter.
func SetMCPProxyCallerAPIID(r *http.Request, proxyAPIID string) {
	mcpProxyCallerAPIIDValue.Set(r, proxyAPIID)
}

// GetMCPProxyCallerAPIID returns the proxy APIID that internally called a
// synthetic REST-as-MCP adapter.
func GetMCPProxyCallerAPIID(r *http.Request) string {
	return mcpProxyCallerAPIIDValue.Get(r)
}

// ContextWithMCPProxyCallerAPIID returns a context carrying the proxy APIID
// that internally called a synthetic REST-as-MCP adapter.
func ContextWithMCPProxyCallerAPIID(parent context.Context, proxyAPIID string) context.Context {
	return context.WithValue(parent, mcpProxyCallerAPIIDKey{}, proxyAPIID)
}

// MCPProxyCallerAPIIDFromContext returns the proxy APIID that internally called
// a synthetic REST-as-MCP adapter.
func MCPProxyCallerAPIIDFromContext(parent context.Context) string {
	if val := parent.Value(mcpProxyCallerAPIIDKey{}); val != nil {
		if proxyAPIID, ok := val.(string); ok {
			return proxyAPIID
		}
	}
	return ""
}
