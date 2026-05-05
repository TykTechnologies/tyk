package gateway

import (
	"net/http"
	"strings"
)

// mcpInboundHeaderPrefix is the lowercased prefix used to identify
// X-Tyk-MCP-* headers that must never be honoured from inbound traffic.
//
// See RFC-API-TO-MCP-V7 §8.2 step 2 and §13: external clients (including
// agent SDKs) may attempt to spoof MCP context headers to influence
// downstream MCP-proxied behaviour. The gateway must drop them
// unconditionally on ingress, before any downstream handler can read them.
const mcpInboundHeaderPrefix = "x-tyk-mcp-"

// StripInboundMCPHeadersMiddleware removes any X-Tyk-MCP-* headers from
// the inbound request. These headers are reserved for internal use by the
// MCP-proxy data path; allowing inbound copies through would let agents
// forge MCP context. The strip is unconditional on the request.
type StripInboundMCPHeadersMiddleware struct {
	*BaseMiddleware
}

// Name returns the middleware identifier used in chain logging.
func (m *StripInboundMCPHeadersMiddleware) Name() string {
	return "StripInboundMCPHeaders"
}

// EnabledForSpec activates the middleware when the API spec carries an
// MCPProxy extension on its Server block (RFC §8.2 / sub-task A2). The
// gating mirrors MCPHandlerMiddleware.EnabledForSpec — both run only on
// Proxy APIDefs, and the strip MUST run before the handler so any inbound
// X-Tyk-MCP-* spoof attempts are dropped before they can be observed by
// downstream code.
func (m *StripInboundMCPHeadersMiddleware) EnabledForSpec() bool {
	if m == nil || m.Spec == nil {
		return false
	}
	if !m.Spec.IsOAS {
		return false
	}
	ext := m.Spec.OAS.GetTykExtension()
	if ext == nil {
		return false
	}
	return ext.Server.MCPProxy != nil
}

// ProcessRequest deletes every header whose canonical name, lowercased,
// starts with "x-tyk-mcp-". http.Header is canonicalised on write, but we
// lowercase defensively so directly-mutated maps are still handled.
func (m *StripInboundMCPHeadersMiddleware) ProcessRequest(_ http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if r == nil || len(r.Header) == 0 {
		return nil, http.StatusOK
	}

	// Collect first, then delete: deleting while ranging over a map is
	// permitted by the Go spec, but collecting keeps the intent obvious
	// and avoids any surprise if the underlying type ever changes.
	var toDelete []string
	for name := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), mcpInboundHeaderPrefix) {
			toDelete = append(toDelete, name)
		}
	}
	for _, name := range toDelete {
		// Delete from the map directly: http.Header.Del canonicalises
		// its argument, which would miss non-canonical keys that a
		// caller (or an upstream that wrote into the map directly)
		// may have inserted. We've already matched case-insensitively
		// against the actual map key, so deleting that key is safe.
		delete(r.Header, name)
	}

	return nil, http.StatusOK
}
