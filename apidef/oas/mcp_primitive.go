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
}
// ExtractToExtendedPaths extracts middleware config, delegating to embedded Operation
// but allowing MCPPrimitive-specific overrides. Notably, response body transformation
// is disabled for MCP primitives to maintain JSON-RPC protocol compliance.
func (m *MCPPrimitive) ExtractToExtendedPaths(ep *apidef.ExtendedPathsSet, path string, method string) {
	if ep == nil || m == nil {
		return
	}

	// Delegate all extractions to the embedded Operation methods, except response body transform.
	m.Operation.extractAllowanceTo(ep, path, method, allow)
	m.Operation.extractAllowanceTo(ep, path, method, block)
	m.Operation.extractAllowanceTo(ep, path, method, ignoreAuthentication)
	m.Operation.extractInternalTo(ep, path, method)
	m.Operation.extractTransformRequestMethodTo(ep, path, method)
	m.Operation.extractTransformRequestBodyTo(ep, path, method)
	// Skip extractTransformResponseBodyTo - MCP responses must be returned as-is
	m.Operation.extractTransformRequestHeadersTo(ep, path, method)
	m.Operation.extractTransformResponseHeadersTo(ep, path, method)
	m.Operation.extractURLRewriteTo(ep, path, method)
	m.Operation.extractCacheTo(ep, path, method)
	m.Operation.extractEnforceTimeoutTo(ep, path, method)
	m.Operation.extractVirtualEndpointTo(ep, path, method)
	m.Operation.extractEndpointPostPluginTo(ep, path, method)
	m.Operation.extractCircuitBreakerTo(ep, path, method)
	m.Operation.extractTrackEndpointTo(ep, path, method)
	m.Operation.extractDoNotTrackEndpointTo(ep, path, method)
	m.Operation.extractRequestSizeLimitTo(ep, path, method)
	m.Operation.extractRateLimitEndpointTo(ep, path, method)
}

// MCPPrimitives maps primitive names to their middleware configurations.
// For tools: key is tool name (e.g., "get-weather").
// For resources: key is resource URI pattern (e.g., "file:///repo/*").
// For prompts: key is prompt name (e.g., "code-review").
type MCPPrimitives map[string]*MCPPrimitive
