package httpctx

import (
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
