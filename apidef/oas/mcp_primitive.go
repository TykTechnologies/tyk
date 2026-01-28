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
//
//nolint:unused // Called from gateway package
func ensureNotBypassingOverride(v interface{}) {
	if _, ok := v.(*Operation); ok {
		panic("BUG: Extracting Operation directly instead of MCPPrimitive - bypasses overrides!")
	}
}

type MCPPrimitives map[string]*MCPPrimitive
