package oas

import (
	"encoding/json"

	"github.com/TykTechnologies/tyk/apidef"
)

// MCPPrimitive holds middleware configuration for MCP primitives (tools, resources, prompts).
// It embeds Operation to reuse all standard middleware (rate limiting, transforms, caching, etc.).
//
// Dual purpose (RFC-API-TO-MCP-V8 §0.2 option 3):
//
//  1. Persisted: per-operation MCP semantics on a regular APIDef, under
//     Middleware.McpTools / McpResources / McpPrompts. The Operation
//     fields (Allow / Block / RateLimit / Transforms / etc.) round-trip
//     through JSON/BSON exactly as before.
//
//  2. Runtime-only: when an MCP Proxy aggregates this APIDef as a
//     source, the gateway populates the lower block of fields below at
//     proxy load (DeriveSourceTools in mcp_proxy_derive.go). These fields
//     are tagged json:"-" bson:"-" — they MUST NOT marshal. They carry
//     the derived tool descriptor that mcpproxy.Handler consumes for
//     tools/list and tools/call request reconstruction.
//
// A single struct serves both roles because their data is disjoint and
// the runtime fields are explicitly non-persisted; nothing on the source
// APIDef's persisted spec encodes the per-proxy namespacing or the
// derived schema.
type MCPPrimitive struct {
	Operation

	// --- runtime-only fields (populated at proxy load) ---

	// ToolName is the full namespaced tool name as exposed to MCP
	// clients: "<source-slug>__<op-name>". Globally unique within a
	// proxy's catalogue.
	ToolName string `json:"-" bson:"-"`

	// SourceSlug identifies which MCP Proxy source contributed this
	// tool. Used by mcpproxy.Handler.findTool to resolve back to the
	// source binding (BackendMode, SourceAPIID, UpstreamURL, UpstreamCred).
	SourceSlug string `json:"-" bson:"-"`

	// Method is the HTTP method derived from the source OAS operation.
	Method string `json:"-" bson:"-"`

	// PathTemplate is the source OAS path with {var} placeholders.
	PathTemplate string `json:"-" bson:"-"`

	// OperationID is the source OAS operationId, when present.
	OperationID string `json:"-" bson:"-"`

	// Description is the source OAS operation description.
	Description string `json:"-" bson:"-"`

	// InputSchema is the synthesised JSON-Schema 2020-12 object schema
	// covering the operation's parameters and JSON requestBody fields
	// (RFC §6.3). Built once at proxy load.
	InputSchema json.RawMessage `json:"-" bson:"-"`

	// OutputSchema mirrors the source OAS response schema when one is
	// declared in a way that survives derivation; empty otherwise.
	OutputSchema json.RawMessage `json:"-" bson:"-"`

	// ParamLocations maps argument name → OAS in: location
	// ("path"|"query"|"header"|"body"). Consumed by request
	// reconstruction in mcpproxy.Handler (RFC §8.3 step 3).
	ParamLocations map[string]string `json:"-" bson:"-"`
}

// extractTransformResponseBodyTo overrides Operation to disable response body transformation.
// MCP responses must be returned as-is to maintain JSON-RPC protocol compliance.
//
//nolint:revive,unparam
func (m *MCPPrimitive) extractTransformResponseBodyTo(_ *apidef.ExtendedPathsSet, _ string, _ string) {
	// Intentionally empty - MCP primitives don't support response body transformation
}

// extractTransformRequestMethodTo disables method transformation for MCP (always POST).
//
//nolint:revive,unparam
func (m *MCPPrimitive) extractTransformRequestMethodTo(_ *apidef.ExtendedPathsSet, _ string, _ string) {
}

// extractInternalTo disables internal endpoint configuration (managed by JSON-RPC router).
//
//nolint:revive,unparam
func (m *MCPPrimitive) extractInternalTo(_ *apidef.ExtendedPathsSet, _ string, _ string) {
}

// extractURLRewriteTo disables URL rewriting (MCP uses fixed paths).
//
//nolint:revive,unparam
func (m *MCPPrimitive) extractURLRewriteTo(_ *apidef.ExtendedPathsSet, _ string, _ string) {
}

// extractCacheTo disables per-endpoint caching (incompatible with JSON-RPC).
//
//nolint:revive,unparam
func (m *MCPPrimitive) extractCacheTo(_ *apidef.ExtendedPathsSet, _ string, _ string) {
}

// extractValidateRequestTo disables OAS validation (handled by JSON-RPC middleware).
//
//nolint:revive,unparam
func (m *MCPPrimitive) extractValidateRequestTo(_ *apidef.ExtendedPathsSet, _ string, _ string) {
}

// extractMockResponseTo disables mock responses (incompatible with JSON-RPC protocol).
//
//nolint:revive,unparam
func (m *MCPPrimitive) extractMockResponseTo(_ *apidef.ExtendedPathsSet, _ string, _ string) {
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
	m.extractTransformResponseBodyTo(ep, path, method)
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
