package oas

import "github.com/TykTechnologies/tyk/apidef"

// MCPPrimitive holds middleware configuration for MCP primitives (tools, resources, prompts).
// It embeds Operation to reuse all standard middleware (rate limiting, transforms, caching, etc.).
type MCPPrimitive struct {
	Operation
}

// extractTransformResponseBodyTo overrides Operation to disable response body transformation.
// MCP responses must be returned as-is to maintain JSON-RPC protocol compliance.
//
//nolint:unused,revive,unparam
func (m *MCPPrimitive) extractTransformResponseBodyTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	// Intentionally empty - MCP primitives don't support response body transformation
	return
}

// ensureNotBypassingOverride validates that the caller passed *MCPPrimitive and not *Operation.
// This development helper catches accidental usage of &primitive.Operation which would bypass overrides.
func ensureNotBypassingOverride(v interface{}) {
	if _, ok := v.(*Operation); ok {
		panic("BUG: Extracting Operation directly instead of MCPPrimitive - bypasses overrides!")
	}
}

// MCPPrimitives maps primitive names to their middleware configurations.
// For tools: key is tool name (e.g., "get-weather").
// For resources: key is resource URI pattern (e.g., "file:///repo/*").
// For prompts: key is prompt name (e.g., "code-review").
type MCPPrimitives map[string]*MCPPrimitive
