// Package mcp provides utilities for MCP (Model Context Protocol) handling.
package mcp

import "strings"

// VEM path prefixes for different MCP primitive types.
const (
	ToolPrefix     = "/mcp-tool:"
	ResourcePrefix = "/mcp-resource:"
	PromptPrefix   = "/mcp-prompt:"
)

// SanitizeName converts primitive names to URL-safe format.
// For resource patterns like "file:///repo/*", converts to "file__repo_*"
func SanitizeName(name string) string {
	result := strings.ReplaceAll(name, "://", "_")
	result = strings.ReplaceAll(result, "/", "_")
	result = strings.ReplaceAll(result, ":", "_")
	return result
}
