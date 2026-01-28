// Package mcp provides utilities for MCP (Model Context Protocol) handling.
package mcp

import "strings"

// VEM path prefixes for different MCP primitive types.
const (
	ToolPrefix      = "/mcp-tool:"
	ResourcePrefix  = "/mcp-resource:"
	PromptPrefix    = "/mcp-prompt:"
	OperationPrefix = "/mcp-operation:"
)

// IsPrimitiveVEMPath returns true if the path is an MCP primitive VEM path.
// These paths are internal-only and should return 404 when accessed directly.
func IsPrimitiveVEMPath(path string) bool {
	return strings.HasPrefix(path, ToolPrefix) ||
		strings.HasPrefix(path, ResourcePrefix) ||
		strings.HasPrefix(path, PromptPrefix) ||
		strings.HasPrefix(path, OperationPrefix)
}

// SanitizeMethodForPath converts JSON-RPC method names to path-safe format.
// For example: "tools/list" becomes "tools-list".
func SanitizeMethodForPath(method string) string {
	return strings.ReplaceAll(method, "/", "-")
}
