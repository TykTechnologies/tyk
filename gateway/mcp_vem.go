package gateway

import (
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/mcp"
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
		spec := a.buildMCPPrimitiveSpec(name, "tool", mcp.ToolPrefix, op, conf)
		specs = append(specs, spec)
		apiSpec.MCPPrimitives["tool:"+name] = mcp.ToolPrefix + mcp.SanitizeName(name)
	}

	// Generate resource VEMs
	for pattern, op := range middleware.McpResources {
		spec := a.buildMCPPrimitiveSpec(pattern, "resource", mcp.ResourcePrefix, op, conf)
		specs = append(specs, spec)
		apiSpec.MCPPrimitives["resource:"+pattern] = mcp.ResourcePrefix + mcp.SanitizeName(pattern)
	}

	// Generate prompt VEMs
	for name, op := range middleware.McpPrompts {
		spec := a.buildMCPPrimitiveSpec(name, "prompt", mcp.PromptPrefix, op, conf)
		specs = append(specs, spec)
		apiSpec.MCPPrimitives["prompt:"+name] = mcp.PromptPrefix + mcp.SanitizeName(name)
	}

	return specs
}

// buildMCPPrimitiveSpec creates a URLSpec for an MCP primitive
func (a APIDefinitionLoader) buildMCPPrimitiveSpec(name, primType, prefix string, op *oas.Operation, conf config.Config) URLSpec {
	path := prefix + mcp.SanitizeName(name)

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
