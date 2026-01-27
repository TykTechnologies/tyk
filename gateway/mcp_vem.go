package gateway

import (
	"strings"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
)

// MCP VEM path prefixes for different primitive types
const (
	MCPToolPrefix     = "/mcp-tool:"
	MCPResourcePrefix = "/mcp-resource:"
	MCPPromptPrefix   = "/mcp-prompt:"
)

// generateMCPVEMs generates URLSpec entries for MCP primitives (tools, resources, prompts).
// These VEMs are internal-only endpoints accessible via JSON-RPC routing.
func (a APIDefinitionLoader) generateMCPVEMs(apiSpec *APISpec, conf config.Config) []URLSpec {
	if !apiSpec.IsMCP() {
		return nil
	}

	middleware := apiSpec.OAS.GetTykMiddleware()
	if middleware == nil {
		return nil
	}

	var specs []URLSpec

	// Initialize MCPPrimitives map
	if apiSpec.MCPPrimitives == nil {
		apiSpec.MCPPrimitives = make(map[string]string)
	}

	// Generate tool VEMs
	for name, op := range middleware.McpTools {
		spec := a.buildMCPPrimitiveSpec(name, "tool", MCPToolPrefix, op, conf)
		specs = append(specs, spec)
		apiSpec.MCPPrimitives["tool:"+name] = MCPToolPrefix + sanitizeMCPName(name)
	}

	// Generate resource VEMs
	for pattern, op := range middleware.McpResources {
		spec := a.buildMCPPrimitiveSpec(pattern, "resource", MCPResourcePrefix, op, conf)
		specs = append(specs, spec)
		apiSpec.MCPPrimitives["resource:"+pattern] = MCPResourcePrefix + sanitizeMCPName(pattern)
	}

	// Generate prompt VEMs
	for name, op := range middleware.McpPrompts {
		spec := a.buildMCPPrimitiveSpec(name, "prompt", MCPPromptPrefix, op, conf)
		specs = append(specs, spec)
		apiSpec.MCPPrimitives["prompt:"+name] = MCPPromptPrefix + sanitizeMCPName(name)
	}

	return specs
}

// buildMCPPrimitiveSpec creates a URLSpec for an MCP primitive
func (a APIDefinitionLoader) buildMCPPrimitiveSpec(name, primType, prefix string, op *oas.Operation, conf config.Config) URLSpec {
	path := prefix + sanitizeMCPName(name)

	spec := URLSpec{
		Status: MCPPrimitive,
		MCPPrimitiveMeta: MCPPrimitiveMeta{
			Name:      name,
			Type:      primType,
			Method:    "POST", // JSON-RPC always uses POST
			Operation: op,
		},
	}

	// Generate regex for path matching
	a.generateRegex(path, &spec, MCPPrimitive, conf)

	return spec
}

// sanitizeMCPName converts primitive names to URL-safe format.
// For resource patterns like "file:///repo/*", converts to "file___repo_*"
func sanitizeMCPName(name string) string {
	result := strings.ReplaceAll(name, "://", "_")
	result = strings.ReplaceAll(result, "/", "_")
	result = strings.ReplaceAll(result, ":", "_")
	return result
}
