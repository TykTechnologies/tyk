// Package mcp provides utilities for MCP (Model Context Protocol) handling.
package mcp

import (
	"strings"
	"sync"

	"github.com/TykTechnologies/tyk/internal/agentprotocol"
)

// VEM path prefixes for different MCP primitive types.
// MCP defines three core primitives: Tools, Resources, and Prompts.
const (
	ToolPrefix     = "/mcp-tool:"
	ResourcePrefix = "/mcp-resource:"
	PromptPrefix   = "/mcp-prompt:"
)

var registerOnce sync.Once

// RegisterVEMPrefixes registers MCP VEM prefixes with the agent protocol registry.
// This is called automatically when needed via sync.Once.
func RegisterVEMPrefixes() {
	registerOnce.Do(func() {
		agentprotocol.RegisterVEMPrefix(ToolPrefix)
		agentprotocol.RegisterVEMPrefix(ResourcePrefix)
		agentprotocol.RegisterVEMPrefix(PromptPrefix)
	})
}

// IsPrimitiveVEMPath returns true if the path is an MCP primitive VEM path.
// These paths are internal-only and should return 404 when accessed directly.
func IsPrimitiveVEMPath(path string) bool {
	return strings.HasPrefix(path, ToolPrefix) ||
		strings.HasPrefix(path, ResourcePrefix) ||
		strings.HasPrefix(path, PromptPrefix)
}
