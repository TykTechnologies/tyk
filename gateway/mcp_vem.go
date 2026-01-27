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

// generateMCPVEMs generates URLSpec entries for MCP primitives (tools, resources, prompts).
// These VEMs are internal-only endpoints accessible via JSON-RPC routing.
func (a APIDefinitionLoader) generateMCPVEMs(apiSpec *APISpec, conf config.Config) []URLSpec {
	// MCP definition detection: require BOTH application protocol and JSON-RPC 2.0.
	if !apiSpec.IsMCP() || apiSpec.JsonRpcVersion != apidef.JsonRPC20 {
		return nil
	}

	middleware := apiSpec.OAS.GetTykMiddleware()
	if middleware == nil {
		return nil
	}

	var specs []URLSpec

	// Always re-init MCPPrimitives on load to avoid stale entries on reload.
	apiSpec.MCPPrimitives = make(map[string]string)

	// Generate tool VEMs
	for name, op := range middleware.McpTools {
		vemPath := mcp.ToolPrefix + name
		specs = append(specs, a.buildMCPPrimitiveSpec(name, "tool", vemPath)...)
		specs = append(specs, a.compileMCPPrimitiveMiddlewareSpecs(op, vemPath, apiSpec, conf)...)
		apiSpec.MCPPrimitives["tool:"+name] = vemPath
	}

	// Generate resource VEMs
	for pattern, op := range middleware.McpResources {
		vemPath := mcp.ResourcePrefix + pattern
		specs = append(specs, a.buildMCPPrimitiveSpec(pattern, "resource", vemPath)...)
		specs = append(specs, a.compileMCPPrimitiveMiddlewareSpecs(op, vemPath, apiSpec, conf)...)
		apiSpec.MCPPrimitives["resource:"+pattern] = vemPath
	}

	// Generate prompt VEMs
	for name, op := range middleware.McpPrompts {
		vemPath := mcp.PromptPrefix + name
		specs = append(specs, a.buildMCPPrimitiveSpec(name, "prompt", vemPath)...)
		specs = append(specs, a.compileMCPPrimitiveMiddlewareSpecs(op, vemPath, apiSpec, conf)...)
		apiSpec.MCPPrimitives["prompt:"+name] = vemPath
	}

	return specs
}

// buildMCPPrimitiveSpec creates the base URLSpec entry for an MCP primitive VEM.
// This is used for access control (blocking direct external access).
func (a APIDefinitionLoader) buildMCPPrimitiveSpec(name, primType, path string) []URLSpec {
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

func (a APIDefinitionLoader) compileMCPPrimitiveMiddlewareSpecs(op *oas.Operation, path string, apiSpec *APISpec, conf config.Config) []URLSpec {
	if op == nil {
		return nil
	}

	var ep apidef.ExtendedPathsSet
	op.ExtractToExtendedPaths(&ep, path, http.MethodPost)

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
