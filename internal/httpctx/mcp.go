package httpctx

import (
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
)

var mcpRoutingValue = NewValue[bool](ctx.MCPRouting)

// SetMCPRouting sets the MCP routing flag in the request context.
// This is used by the JSON-RPC router to indicate that a request is being
// routed internally to an MCP primitive VEM.
func SetMCPRouting(r *http.Request, enabled bool) {
	mcpRoutingValue.Set(r, enabled)
}

// IsMCPRouting returns true if the request came via MCP JSON-RPC routing.
// This is checked by the access control logic to allow internal VEM access.
func IsMCPRouting(r *http.Request) bool {
	return mcpRoutingValue.Get(r)
}
