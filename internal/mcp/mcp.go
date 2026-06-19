// Package mcp provides utilities for MCP (Model Context Protocol) handling.
package mcp

import (
	"strings"
	"sync"

	"github.com/TykTechnologies/tyk/internal/agentprotocol"
	"github.com/TykTechnologies/tyk/internal/jsonrpc"
)

// VEM path prefixes for different MCP primitive types.
// MCP defines three core primitives: Tools, Resources, and Prompts.
// SW-REQ-025
const (
	ToolPrefix     = "/mcp-tool:"
	ResourcePrefix = "/mcp-resource:"
	PromptPrefix   = "/mcp-prompt:"
)

// WildcardPattern is the mux-style pattern for matching any remaining path segments.
// SW-REQ-025
const WildcardPattern = "{rest:.*}"

// Catch-all patterns for MCP primitive VEMs in allowlist mode.
// Uses mux-style pattern matching: /prefix{rest:.*}
// These patterns match any path starting with the primitive prefix.
// SW-REQ-025
const (
	// ToolCatchAllPattern matches all tool VEM paths.
	// Format: /mcp-tool:{rest:.*}
	ToolCatchAllPattern = ToolPrefix + WildcardPattern

	// ResourceCatchAllPattern matches all resource VEM paths.
	// Format: /mcp-resource:{rest:.*}
	ResourceCatchAllPattern = ResourcePrefix + WildcardPattern

	// PromptCatchAllPattern matches all prompt VEM paths.
	// Format: /mcp-prompt:{rest:.*}
	PromptCatchAllPattern = PromptPrefix + WildcardPattern
)

var registerOnce sync.Once

// RegisterVEMPrefixes registers MCP and JSON-RPC VEM prefixes with the agent protocol registry.
// This is called automatically when needed via sync.Once.
// SW-REQ-025
func RegisterVEMPrefixes() {
	registerOnce.Do(func() {
		// Register MCP-specific primitive VEM prefixes
		agentprotocol.RegisterVEMPrefix(ToolPrefix)
		agentprotocol.RegisterVEMPrefix(ResourcePrefix)
		agentprotocol.RegisterVEMPrefix(PromptPrefix)
		// Register generic JSON-RPC operation VEM prefix
		agentprotocol.RegisterVEMPrefix(jsonrpc.MethodVEMPrefix)
	})
}

// IsPrimitiveVEMPath returns true if the path is an MCP primitive VEM path.
// These paths are internal-only and should return 404 when accessed directly.
// SW-REQ-025
func IsPrimitiveVEMPath(path string) bool {
	return strings.HasPrefix(path, ToolPrefix) ||
		strings.HasPrefix(path, ResourcePrefix) ||
		strings.HasPrefix(path, PromptPrefix)
}
