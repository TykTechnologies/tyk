package oas

import (
	"fmt"
)

// ValidateRemoteMCPToolOverrides validates x-tyk-mcp-server primitives for a
// remote MCP proxy, where each primitive selects an upstream tool by
// source.toolName and may override its name, description and annotations.
//
// It checks only what the configuration itself can prove: selectors, tool-name
// syntax, duplicate sources and duplicate final names. Swapping names between
// overridden tools, or reusing a name freed by another override, is allowed.
// Collisions with upstream tools that have no override need the upstream
// catalogue; see CheckRemoteMCPToolCatalogue.
func ValidateRemoteMCPToolOverrides(ext *TykMCPServer) error {
	if ext == nil {
		return nil
	}

	sources := make(map[string]struct{}, len(ext.Primitives))
	finalNames := make(map[string]struct{}, len(ext.Primitives))
	for i, primitive := range ext.Primitives {
		source := primitive.Source
		if source.OperationID != "" || source.Path != "" || source.Method != "" {
			return fmt.Errorf("%s primitive %d: operationId and path+method selectors are valid only for MCP proxies targeting a REST-as-MCP adapter; use source.toolName", ExtensionTykMCPServer, i)
		}
		toolName := source.ToolName
		if toolName == "" {
			return fmt.Errorf("%s primitive %d: source.toolName is required on remote MCP proxies", ExtensionTykMCPServer, i)
		}
		if err := ValidateMCPToolName(toolName); err != nil {
			return fmt.Errorf("%s primitive %d: source.toolName %q is not a valid tool name: %w", ExtensionTykMCPServer, i, toolName, err)
		}
		if len(primitive.Parameters) > 0 {
			return fmt.Errorf("%s primitive %q: parameters are not supported on remote MCP proxies", ExtensionTykMCPServer, toolName)
		}
		if primitive.Allow != nil {
			return fmt.Errorf("%s primitive %q: allow is not supported on remote MCP proxies; use tool access rules instead", ExtensionTykMCPServer, toolName)
		}
		if _, dup := sources[toolName]; dup {
			return fmt.Errorf("%s has duplicate source.toolName %q", ExtensionTykMCPServer, toolName)
		}
		sources[toolName] = struct{}{}

		finalName := toolName
		if primitive.Name != "" {
			if err := ValidateMCPToolName(primitive.Name); err != nil {
				return fmt.Errorf("%s primitive %q: %w", ExtensionTykMCPServer, toolName, err)
			}
			finalName = primitive.Name
		}
		if _, dup := finalNames[finalName]; dup {
			return fmt.Errorf("%s: %q is a duplicate tool name", ExtensionTykMCPServer, finalName)
		}
		finalNames[finalName] = struct{}{}
	}
	return nil
}
