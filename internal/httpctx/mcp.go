package httpctx

import (
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
)

var mcpProtocolContextValue = NewValue[*mcp.ProtocolContext](ctx.MCPProtocolContext)

// SetMCPProtocolContext stores the normalized MCP ingress context.
func SetMCPProtocolContext(r *http.Request, protocolContext *mcp.ProtocolContext) {
	mcpProtocolContextValue.Set(r, protocolContext)
}

// GetMCPProtocolContext returns the normalized MCP ingress context.
func GetMCPProtocolContext(r *http.Request) *mcp.ProtocolContext {
	return mcpProtocolContextValue.Get(r)
}
