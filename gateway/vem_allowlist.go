package gateway

import (
	"github.com/TykTechnologies/tyk/apidef/oas"
)

type PrimitiveCategory struct {
	Prefix     string
	TypeName   string
	Primitives oas.MCPPrimitives
}

// hasOperationAllowEnabled checks if any operation has allow middleware enabled.
// Operations are path-level configurations in OAS (e.g., operationId-based middleware).
// This is generic JSON-RPC logic, not specific to MCP.
func hasOperationAllowEnabled(operations oas.Operations) bool {
	for _, op := range operations {
		if op != nil && op.Allow != nil && op.Allow.Enabled {
			return true
		}
	}
	return false
}

// hasPrimitiveAllowEnabled checks if any primitive has allow middleware enabled.
// Primitives are protocol-specific resources (MCP tools/resources/prompts, A2A actions, etc.).
// This is generic for any protocol that uses MCPPrimitives structure.
func hasPrimitiveAllowEnabled(primitives oas.MCPPrimitives) bool {
	for _, primitive := range primitives {
		if primitive != nil && primitive.Allow != nil && primitive.Allow.Enabled {
			return true
		}
	}
	return false
}

// hasAllowListEnabled checks if allow middleware is enabled at either the operation level
// (path-based) or primitive level (protocol-specific resources).
// This unified function supports whitelist mode for any JSON-RPC-based protocol.
//
// When this returns true, whitelist mode is active:
// - Only explicitly allowed endpoints (with Allow.Enabled) are accessible
// - All other endpoints are blocked by catch-all BlackList VEMs
func hasAllowListEnabled(operations oas.Operations, categories []PrimitiveCategory) bool {
	// Check operation-level allows (path/operationId-based)
	if hasOperationAllowEnabled(operations) {
		return true
	}

	// Check primitive-level allows (protocol-specific)
	for _, cat := range categories {
		if hasPrimitiveAllowEnabled(cat.Primitives) {
			return true
		}
	}

	return false
}
