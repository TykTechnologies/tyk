package gateway

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/jsonrpc"
	"github.com/TykTechnologies/tyk/internal/mcp"
	tykregexp "github.com/TykTechnologies/tyk/regexp"
)

// PrimitiveCategory defines a category of JSON-RPC primitives to generate VEMs for.
// This allows different protocols (MCP, A2A) to share the same VEM generation logic.
type PrimitiveCategory struct {
	// Prefix is the VEM path prefix (e.g., "/mcp-tool:").
	Prefix string
	// TypeName is the type identifier used for primitive map keys (e.g., "tool").
	TypeName string
	// Primitives maps primitive names to their middleware configurations.
	Primitives oas.MCPPrimitives
}

// generateJSONRPCVEMs generates URLSpec entries for JSON-RPC primitives.
// This is a generic function usable for MCP, A2A, or other JSON-RPC protocols.
// It requires JSON-RPC 2.0 and populates primitivesMap with generated VEM paths.
//
// All registered primitives get Internal entries (required for JSON-RPC routing).
// Primitives with Allow.Enabled also get WhiteList entries via extractAllowanceTo.
// Primitives without Allow are blocked by the catch-all BlackList in whitelist mode.
func (a APIDefinitionLoader) generateJSONRPCVEMs(
	apiSpec *APISpec,
	conf config.Config,
	categories []PrimitiveCategory,
	primitivesMap map[string]string,
) []URLSpec {
	if apiSpec.JsonRpcVersion != apidef.JsonRPC20 {
		return nil
	}

	var specs []URLSpec
	for _, cat := range categories {
		for name, op := range cat.Primitives {
			vemPath := cat.Prefix + name

			// All registered primitives get Internal entries for JSON-RPC routing.
			// The blocking logic for primitives without Allow happens via:
			// 1. No WhiteList entry generated (extractAllowanceTo skips if Allow is nil)
			// 2. Catch-all BlackList blocks anything without a WhiteList match
			specs = append(specs, a.buildPrimitiveSpec(name, cat.TypeName, vemPath)...)
			specs = append(specs, a.compilePrimitiveMiddlewareSpecs(op, vemPath, apiSpec, conf)...)
			// Use consistent key format
			primitiveKey := cat.TypeName + ":" + name
			primitivesMap[primitiveKey] = vemPath
		}
	}

	return specs
}

// generateMCPVEMs generates URLSpec entries for MCP primitives (tools, resources, prompts).
// These VEMs are internal-only endpoints accessible via JSON-RPC routing.
// It also pre-calculates MCPAllowListEnabled to avoid iterating through primitives on each request.
//
// When MCPAllowListEnabled is true (at least one primitive has Allow.Enabled), this function
// also generates catch-all BlackList VEMs for each primitive type. These catch-alls block
// any MCP primitive that doesn't have an explicit Allow entry, enabling proper whitelist behavior.
func (a APIDefinitionLoader) generateMCPVEMs(apiSpec *APISpec, conf config.Config) []URLSpec {
	if !apiSpec.IsMCP() {
		return nil
	}

	// Ensure MCP VEM prefixes are registered with the agent protocol registry.
	mcp.RegisterVEMPrefixes()

	middleware := apiSpec.OAS.GetTykMiddleware()
	if middleware == nil {
		return nil
	}

	// Always re-init MCPPrimitives on load to avoid stale entries on reload.
	apiSpec.MCPPrimitives = make(map[string]string)

	categories := []PrimitiveCategory{
		{Prefix: mcp.ToolPrefix, TypeName: "tool", Primitives: middleware.McpTools},
		{Prefix: mcp.ResourcePrefix, TypeName: "resource", Primitives: middleware.McpResources},
		{Prefix: mcp.PromptPrefix, TypeName: "prompt", Primitives: middleware.McpPrompts},
	}

	// Pre-calculate allowlist flags independently for each category.
	// This provides granular control: operations, tools, resources, and prompts
	// each have independent allowlist modes.
	operations := oas.Operations{}
	if middleware.Operations != nil {
		operations = middleware.Operations
	}

	// Set independent flags per category
	apiSpec.OperationsAllowListEnabled = hasOperationAllowEnabled(operations)
	apiSpec.ToolsAllowListEnabled = hasPrimitiveAllowEnabled(middleware.McpTools)
	apiSpec.ResourcesAllowListEnabled = hasPrimitiveAllowEnabled(middleware.McpResources)
	apiSpec.PromptsAllowListEnabled = hasPrimitiveAllowEnabled(middleware.McpPrompts)

	// MCPAllowListEnabled is a convenience flag that's true if ANY MCP primitive has allow enabled
	apiSpec.MCPAllowListEnabled = apiSpec.ToolsAllowListEnabled ||
		apiSpec.ResourcesAllowListEnabled ||
		apiSpec.PromptsAllowListEnabled

	specs := a.generateJSONRPCVEMs(apiSpec, conf, categories, apiSpec.MCPPrimitives)
	if specs == nil {
		return nil
	}

	// Generate operation VEMs for JSON-RPC methods (tools/call, resources/read, etc.)
	// These allow operation-level middleware to be applied before primitive-level middleware
	specs = append(specs, a.generateMCPOperationVEMs(apiSpec, conf)...)

	return specs
}

// mcpOperationVEMPaths maps JSON-RPC method names to their operation VEM paths.
// These are used both for VEM generation and for building the VEM chain at runtime.
// Operation VEMs use generic JSON-RPC naming (/json-rpc-method:) not MCP-specific naming.
var mcpOperationVEMPaths = map[string]string{
	mcp.MethodToolsCall:     jsonrpc.MethodVEMPrefix + mcp.MethodToolsCall,
	mcp.MethodResourcesRead: jsonrpc.MethodVEMPrefix + mcp.MethodResourcesRead,
	mcp.MethodPromptsGet:    jsonrpc.MethodVEMPrefix + mcp.MethodPromptsGet,
}

// generateMCPOperationVEMs creates VEMs for JSON-RPC operations (tools/call, resources/read, prompts/get).
// Operation VEMs allow operation-level middleware to be applied before routing to specific primitives.
// The VEM chain is: listenPath → operation VEM → primitive VEM.
//
// Path matching: The OAS path (e.g., "/tools/call") is matched against JSON-RPC method names.
// For each matching path, the operation's middleware is compiled for the corresponding operation VEM.
func (a APIDefinitionLoader) generateMCPOperationVEMs(apiSpec *APISpec, conf config.Config) []URLSpec {
	middleware := apiSpec.OAS.GetTykMiddleware()
	if middleware == nil || middleware.Operations == nil {
		return nil
	}

	// Check if the OAS has paths defined
	if apiSpec.OAS.Paths == nil {
		return nil
	}

	var specs []URLSpec

	// Iterate over OAS paths to find ones that match JSON-RPC method names
	for path, pathItem := range apiSpec.OAS.Paths.Map() {
		if pathItem == nil {
			continue
		}

		// Check if the path matches a known JSON-RPC method
		// Remove leading slash from path for comparison (e.g., "/tools/call" -> "tools/call")
		methodName := strings.TrimPrefix(path, "/")
		operationVEMPath, ok := mcpOperationVEMPaths[methodName]
		if !ok {
			continue
		}

		// Find the operation ID for this path (check all HTTP methods)
		opID := findOperationID(pathItem)
		if opID == "" {
			continue
		}

		// Get the operation middleware config
		op := middleware.Operations[opID]
		if op == nil {
			continue
		}

		// Create Internal VEM for this operation
		specs = append(specs, a.buildPrimitiveSpec(opID, "operation", operationVEMPath)...)

		// Extract and compile operation-level middleware for this VEM
		specs = append(specs, a.compileOperationMiddlewareSpecs(op, operationVEMPath, apiSpec, conf)...)
	}

	return specs
}

// findOperationID extracts the operation ID from a PathItem.
// It checks all HTTP methods and returns the first non-empty operation ID found.
func findOperationID(pathItem *openapi3.PathItem) string {
	operations := []*openapi3.Operation{
		pathItem.Get,
		pathItem.Post,
		pathItem.Put,
		pathItem.Patch,
		pathItem.Delete,
		pathItem.Head,
		pathItem.Options,
		pathItem.Trace,
	}

	for _, op := range operations {
		if op != nil && op.OperationID != "" {
			return op.OperationID
		}
	}
	return ""
}

// compileOperationMiddlewareSpecs extracts and compiles middleware for an operation VEM.
func (a APIDefinitionLoader) compileOperationMiddlewareSpecs(op *oas.Operation, path string, apiSpec *APISpec, conf config.Config) []URLSpec {
	if op == nil {
		return nil
	}

	var ep apidef.ExtendedPathsSet
	op.ExtractToExtendedPaths(&ep, path, http.MethodPost)

	// Compile middleware specs (same pipeline as primitive middleware)
	specs := []URLSpec{}
	specs = append(specs, a.compileMockResponsePathSpec(false, ep.MockResponse, MockResponse, conf)...)
	specs = append(specs, a.compileExtendedPathSpec(false, ep.Ignored, Ignored, conf)...)
	specs = append(specs, a.compileExtendedPathSpec(false, ep.BlackList, BlackList, conf)...)
	specs = append(specs, a.compileExtendedPathSpec(false, ep.WhiteList, WhiteList, conf)...)
	specs = append(specs, a.compileCachedPathSpec(ep.Cached, ep.AdvanceCacheConfig, conf)...)
	specs = append(specs, a.compileTransformPathSpec(ep.Transform, Transformed, conf)...)
	specs = append(specs, a.compileTransformPathSpec(ep.TransformResponse, TransformedResponse, conf)...)
	specs = append(specs, a.compileTransformJQPathSpec(ep.TransformJQ, TransformedJQ)...)
	specs = append(specs, a.compileTransformJQPathSpec(ep.TransformJQResponse, TransformedJQResponse)...)
	specs = append(specs, a.compileInjectedHeaderSpec(ep.TransformHeader, HeaderInjected, conf)...)
	specs = append(specs, a.compileInjectedHeaderSpec(ep.TransformResponseHeader, HeaderInjectedResponse, conf)...)
	specs = append(specs, a.compileTimeoutPathSpec(ep.HardTimeouts, HardTimeout, conf)...)
	specs = append(specs, a.compileCircuitBreakerPathSpec(ep.CircuitBreaker, CircuitBreaker, apiSpec, conf)...)
	specs = append(specs, a.compileURLRewritesPathSpec(ep.URLRewrite, URLRewrite, conf)...)
	specs = append(specs, a.compileVirtualPathsSpec(ep.Virtual, VirtualPath, apiSpec, conf)...)
	specs = append(specs, a.compileRequestSizePathSpec(ep.SizeLimit, RequestSizeLimit, conf)...)
	specs = append(specs, a.compileMethodTransformSpec(ep.MethodTransforms, MethodTransformed, conf)...)
	specs = append(specs, a.compileTrackedEndpointPathsSpec(ep.TrackEndpoints, RequestTracked, conf)...)
	specs = append(specs, a.compileUnTrackedEndpointPathsSpec(ep.DoNotTrackEndpoints, RequestNotTracked, conf)...)
	specs = append(specs, a.compileValidateJSONPathsSpec(ep.ValidateJSON, ValidateJSONRequest, conf)...)
	specs = append(specs, a.compileInternalPathsSpec(ep.Internal, Internal, conf)...)
	specs = append(specs, a.compileGopluginPathsSpec(ep.GoPlugin, GoPlugin, apiSpec, conf)...)
	specs = append(specs, a.compileRateLimitPathsSpec(ep.RateLimit, RateLimit, conf)...)

	return specs
}

// buildCatchAllSpecs creates catch-all BlackList VEMs for the given prefixes.
// When allowlist mode is active for a category, its catch-all blocks any endpoint
// in that category without an explicit Allow entry.
// Uses the standard compileExtendedPathSpec to ensure consistent regex generation.
func (a APIDefinitionLoader) buildCatchAllSpecs(prefixes []string, conf config.Config) []URLSpec {
	var blacklistPaths []apidef.EndPointMeta

	for _, prefix := range prefixes {
		// Use wildcard pattern "/*" which PreparePathRegexp converts to "/.*" regex.
		// This matches any path starting with the prefix.
		blacklistPaths = append(blacklistPaths, apidef.EndPointMeta{
			Path:   prefix,
			Method: http.MethodPost,
		})
	}

	return a.compileExtendedPathSpec(false, blacklistPaths, BlackList, conf)
}

// hasMCPAllowListEnabled checks if any MCP primitive has an allow rule enabled.
// This is MCP-specific and delegates to the generic hasPrimitiveAllowEnabled utility.
func hasMCPAllowListEnabled(categories []PrimitiveCategory) bool {
	for _, cat := range categories {
		if hasPrimitiveAllowEnabled(cat.Primitives) {
			return true
		}
	}
	return false
}

// buildPrimitiveSpec creates the base URLSpec entry for a JSON-RPC primitive VEM.
// This is used for access control (blocking direct external access).
//
// Note: This uses manual regex creation with QuoteMeta because MCP VEM paths must
// be matched literally. Unlike OAS paths which may contain mux templates ({id}) or
// wildcards (/*), MCP primitive names/URIs can contain regex metacharacters (., *)
// that should be treated as literals.
//
// Parameters name and primType are currently unused but retained in the signature
// for future use (e.g., logging, metrics, or extended metadata). Use blank identifiers
// to satisfy the linter until needed.
func (a APIDefinitionLoader) buildPrimitiveSpec(_, _, path string) []URLSpec {
	spec := URLSpec{
		Status: Internal,
		Internal: apidef.InternalMeta{
			Path:   path,
			Method: http.MethodPost, // JSON-RPC always uses POST
		},
	}

	// VEM paths must be matched literally (primitive names/patterns can contain regex meta).
	re, err := tykregexp.Compile("^" + regexp.QuoteMeta(path) + "$")
	if err == nil {
		spec.spec = re
	}

	return []URLSpec{spec}
}

func (a APIDefinitionLoader) compilePrimitiveMiddlewareSpecs(primitive *oas.MCPPrimitive, path string, apiSpec *APISpec, conf config.Config) []URLSpec {
	if primitive == nil {
		return nil
	}

	var ep apidef.ExtendedPathsSet
	primitive.ExtractToExtendedPaths(&ep, path, http.MethodPost)

	// Reuse the classic middleware compilation pipeline for per-path middleware.
	specs := []URLSpec{}
	specs = append(specs, a.compileMockResponsePathSpec(false, ep.MockResponse, MockResponse, conf)...)
	specs = append(specs, a.compileExtendedPathSpec(false, ep.Ignored, Ignored, conf)...)
	specs = append(specs, a.compileExtendedPathSpec(false, ep.BlackList, BlackList, conf)...)
	specs = append(specs, a.compileExtendedPathSpec(false, ep.WhiteList, WhiteList, conf)...)
	specs = append(specs, a.compileCachedPathSpec(ep.Cached, ep.AdvanceCacheConfig, conf)...)
	specs = append(specs, a.compileTransformPathSpec(ep.Transform, Transformed, conf)...)
	specs = append(specs, a.compileTransformPathSpec(ep.TransformResponse, TransformedResponse, conf)...)
	specs = append(specs, a.compileTransformJQPathSpec(ep.TransformJQ, TransformedJQ)...)
	specs = append(specs, a.compileTransformJQPathSpec(ep.TransformJQResponse, TransformedJQResponse)...)
	specs = append(specs, a.compileInjectedHeaderSpec(ep.TransformHeader, HeaderInjected, conf)...)
	specs = append(specs, a.compileInjectedHeaderSpec(ep.TransformResponseHeader, HeaderInjectedResponse, conf)...)
	specs = append(specs, a.compileTimeoutPathSpec(ep.HardTimeouts, HardTimeout, conf)...)
	specs = append(specs, a.compileCircuitBreakerPathSpec(ep.CircuitBreaker, CircuitBreaker, apiSpec, conf)...)
	specs = append(specs, a.compileURLRewritesPathSpec(ep.URLRewrite, URLRewrite, conf)...)
	specs = append(specs, a.compileVirtualPathsSpec(ep.Virtual, VirtualPath, apiSpec, conf)...)
	specs = append(specs, a.compileRequestSizePathSpec(ep.SizeLimit, RequestSizeLimit, conf)...)
	specs = append(specs, a.compileMethodTransformSpec(ep.MethodTransforms, MethodTransformed, conf)...)
	specs = append(specs, a.compileTrackedEndpointPathsSpec(ep.TrackEndpoints, RequestTracked, conf)...)
	specs = append(specs, a.compileUnTrackedEndpointPathsSpec(ep.DoNotTrackEndpoints, RequestNotTracked, conf)...)
	specs = append(specs, a.compileValidateJSONPathsSpec(ep.ValidateJSON, ValidateJSONRequest, conf)...)
	specs = append(specs, a.compileInternalPathsSpec(ep.Internal, Internal, conf)...)
	specs = append(specs, a.compileGopluginPathsSpec(ep.GoPlugin, GoPlugin, apiSpec, conf)...)
	specs = append(specs, a.compileRateLimitPathsSpec(ep.RateLimit, RateLimit, conf)...)

	return specs
}
