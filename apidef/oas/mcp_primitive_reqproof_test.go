package oas

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/mcp"
)

// Verifies: SYS-REQ-107, SW-REQ-048
// SW-REQ-048:nominal:nominal
// SW-REQ-048:encoding_safety:nominal
func TestMCPPrimitiveReqProof_JSONShape(t *testing.T) {
	primitive := &MCPPrimitive{}
	primitive.Allow = &Allowance{Enabled: true}
	primitive.RateLimit = &RateLimitEndpoint{
		Enabled: true,
		Rate:    100,
		Per:     ReadableDuration(time.Minute),
	}

	data, err := json.Marshal(MCPPrimitives{"get-weather": primitive})
	require.NoError(t, err)

	var got MCPPrimitives
	require.NoError(t, json.Unmarshal(data, &got))
	require.Contains(t, got, "get-weather")
	require.NotNil(t, got["get-weather"].Allow)
	require.True(t, got["get-weather"].Allow.Enabled)
	require.NotNil(t, got["get-weather"].RateLimit)
	require.Equal(t, 100, got["get-weather"].RateLimit.Rate)
}

// Verifies: SYS-REQ-107, SW-REQ-048
// SW-REQ-048:boundary:nominal
// SW-REQ-048:boundary:boundary
// SW-REQ-048:nil_safety:nominal
// SW-REQ-048:nil_safety:negative
func TestMCPPrimitiveReqProof_ExtractNilSafety(t *testing.T) {
	var primitive *MCPPrimitive
	var ep apidef.ExtendedPathsSet

	require.NotPanics(t, func() {
		primitive.ExtractToExtendedPaths(&ep, mcp.ToolPrefix+"get-weather", "POST")
	})
	require.Empty(t, ep)

	primitive = &MCPPrimitive{}
	require.NotPanics(t, func() {
		primitive.ExtractToExtendedPaths(nil, mcp.ToolPrefix+"get-weather", "POST")
	})
}

// Verifies: SYS-REQ-107, SW-REQ-048
// SW-REQ-048:nominal:nominal
// SW-REQ-048:access_denied:nominal
// SW-REQ-048:access_denied:negative
// SW-REQ-048:boundary:nominal
// SW-REQ-048:boundary:boundary
func TestMCPPrimitiveReqProof_ExtractDisablesIncompatibleMiddleware(t *testing.T) {
	primitive := &MCPPrimitive{}
	primitive.Internal = &Internal{Enabled: true}
	primitive.TransformRequestMethod = &TransformRequestMethod{Enabled: true, ToMethod: "GET"}
	primitive.TransformResponseBody = &TransformBody{Enabled: true, Format: apidef.RequestJSON, Body: "rewritten"}
	primitive.URLRewrite = &URLRewrite{Enabled: true, Pattern: ".*", RewriteTo: "/rewritten"}
	primitive.Cache = &CachePlugin{Enabled: true, Timeout: 60}
	primitive.ValidateRequest = &ValidateRequest{Enabled: true, ErrorResponseCode: 422}
	primitive.MockResponse = &MockResponse{Enabled: true, Code: 200, Body: `{"ok":true}`}

	var ep apidef.ExtendedPathsSet
	primitive.ExtractToExtendedPaths(&ep, mcp.ToolPrefix+"get-weather", "POST")

	require.Empty(t, ep.Internal)
	require.Empty(t, ep.MethodTransforms)
	require.Empty(t, ep.TransformResponse)
	require.Empty(t, ep.URLRewrite)
	require.Empty(t, ep.AdvanceCacheConfig)
	require.Empty(t, ep.ValidateRequest)
	require.Empty(t, ep.MockResponse)
}

// Verifies: SYS-REQ-107, SW-REQ-048
// SW-REQ-048:nominal:nominal
// SW-REQ-048:determinism:nominal
func TestMCPPrimitiveReqProof_ExtractPreservesAllowedMiddleware(t *testing.T) {
	primitive := &MCPPrimitive{}
	primitive.TransformRequestHeaders = &TransformHeaders{
		Enabled: true,
		Add:     Headers{{Name: "X-MCP", Value: "tool"}},
	}
	primitive.TransformResponseHeaders = &TransformHeaders{
		Enabled: true,
		Add:     Headers{{Name: "X-MCP-Response", Value: "ok"}},
	}
	primitive.RateLimit = &RateLimitEndpoint{
		Enabled: true,
		Rate:    42,
		Per:     ReadableDuration(time.Minute),
	}
	primitive.RequestSizeLimit = &RequestSizeLimit{
		Enabled: true,
		Value:   4096,
	}

	var first apidef.ExtendedPathsSet
	primitive.ExtractToExtendedPaths(&first, mcp.ToolPrefix+"get-weather", "POST")

	var second apidef.ExtendedPathsSet
	primitive.ExtractToExtendedPaths(&second, mcp.ToolPrefix+"get-weather", "POST")

	require.Len(t, first.TransformHeader, 1)
	require.Len(t, first.TransformResponseHeader, 1)
	require.Len(t, first.RateLimit, 1)
	require.Len(t, first.SizeLimit, 1)
	require.Equal(t, first, second)
}
