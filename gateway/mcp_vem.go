package gateway

import (
	"net/http"
	"regexp"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
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
			specs = append(specs, a.buildPrimitiveSpec(name, cat.TypeName, vemPath)...)
			specs = append(specs, a.compilePrimitiveMiddlewareSpecs(op, vemPath, apiSpec, conf)...)
			primitivesMap[cat.TypeName+":"+name] = vemPath
		}
	}

	return specs
}

// generateMCPVEMs generates URLSpec entries for MCP primitives (tools, resources, prompts).
// These VEMs are internal-only endpoints accessible via JSON-RPC routing.
// It also pre-calculates MCPAllowListEnabled to avoid iterating through primitives on each request.
func (a APIDefinitionLoader) generateMCPVEMs(apiSpec *APISpec, conf config.Config) []URLSpec {
	if !apiSpec.IsMCP() {
		return nil
	}

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

	// Pre-calculate whether any MCP primitive has an allow rule enabled.
	// This avoids iterating through all primitives on every JSON-RPC request.
	apiSpec.MCPAllowListEnabled = hasMCPAllowListEnabled(categories)

	return a.generateJSONRPCVEMs(apiSpec, conf, categories, apiSpec.MCPPrimitives)
}

// hasMCPAllowListEnabled checks if any MCP primitive has an allow rule enabled.
func hasMCPAllowListEnabled(categories []PrimitiveCategory) bool {
	for _, cat := range categories {
		for _, primitive := range cat.Primitives {
			if primitive != nil && primitive.Allow != nil && primitive.Allow.Enabled {
				return true
			}
		}
	}
	return false
}

// buildPrimitiveSpec creates the base URLSpec entry for a JSON-RPC primitive VEM.
// This is used for access control (blocking direct external access).
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
