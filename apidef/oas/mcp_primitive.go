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
//nolint:revive,unparam
func (m *MCPPrimitive) extractTransformResponseBodyTo(_ *apidef.ExtendedPathsSet, _ string, _ string) {
	// Intentionally empty - MCP primitives don't support response body transformation
}

// ExtractToExtendedPaths extracts middleware config, delegating to embedded Operation
// but allowing MCPPrimitive-specific overrides. Methods without overrides are promoted
// to Operation. Methods with empty overrides (like extractTransformResponseBodyTo) are
// effectively disabled for MCP primitives.
//
//nolint:dupl // Intentional similarity to Operation.ExtractToExtendedPaths with MCP-specific behavior
func (m *MCPPrimitive) ExtractToExtendedPaths(ep *apidef.ExtendedPathsSet, path string, method string) {
	if ep == nil || m == nil {
		return
	}

	m.extractAllowanceTo(ep, path, method, allow)
	m.extractAllowanceTo(ep, path, method, block)
	m.extractAllowanceTo(ep, path, method, ignoreAuthentication)
	m.extractInternalTo(ep, path, method)
	m.extractTransformRequestMethodTo(ep, path, method)
	m.extractTransformRequestBodyTo(ep, path, method)
	m.extractTransformResponseBodyTo(ep, path, method) // empty override - disabled for MCP
	m.extractTransformRequestHeadersTo(ep, path, method)
	m.extractTransformResponseHeadersTo(ep, path, method)
	m.extractURLRewriteTo(ep, path, method)
	m.extractCacheTo(ep, path, method)
	m.extractEnforceTimeoutTo(ep, path, method)
	m.extractValidateRequestTo(ep, path, method)
	m.extractMockResponseTo(ep, path, method)
	m.extractVirtualEndpointTo(ep, path, method)
	m.extractEndpointPostPluginTo(ep, path, method)
	m.extractCircuitBreakerTo(ep, path, method)
	m.extractTrackEndpointTo(ep, path, method)
	m.extractDoNotTrackEndpointTo(ep, path, method)
	m.extractRequestSizeLimitTo(ep, path, method)
	m.extractRateLimitEndpointTo(ep, path, method)
}

// MCPPrimitives maps primitive names to their middleware configurations.
// For tools: key is tool name (e.g., "get-weather").
// For resources: key is resource URI pattern (e.g., "file:///repo/*").
// For prompts: key is prompt name (e.g., "code-review").
type MCPPrimitives map[string]*MCPPrimitive
