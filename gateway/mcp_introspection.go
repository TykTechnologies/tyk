package gateway

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/mcp/client"
)

// getIntrospectionConfig returns the MCPIntrospection config from an APISpec,
// or nil if the spec is not an MCP API or has no introspection configured.
func getIntrospectionConfig(spec *APISpec) *oas.MCPIntrospection {
	if spec == nil {
		return nil
	}

	ext := spec.OAS.GetTykExtension()
	if ext == nil {
		return nil
	}

	return ext.Server.Introspection
}

// runIntrospection performs a single introspection cycle against the upstream MCP server.
// If no introspection config is present, sensible defaults are used (10s timeout).
func (gw *Gateway) runIntrospection(spec *APISpec) (*client.IntrospectionResult, error) {
	ext := spec.OAS.GetTykExtension()
	if ext == nil {
		return nil, fmt.Errorf("no OAS extension for API %s", spec.APIID)
	}

	cfg := getIntrospectionConfig(spec)
	// Use defaults if no config is present (on-demand introspection).
	var timeoutStr string
	if cfg != nil {
		timeoutStr = cfg.GetTimeout()
	} else {
		timeoutStr = "10s"
	}

	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return nil, fmt.Errorf("parse timeout %q: %w", timeoutStr, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	upstreamURL := ext.Upstream.URL

	c := client.New()
	return c.Introspect(ctx, upstreamURL)
}

// buildDiscoveredPrimitives converts discovered server capabilities into the
// MCPPrimitives map format used by APISpec. It respects the discovery flags
// in the introspection config to filter which primitive types are included.
func buildDiscoveredPrimitives(caps *client.ServerCapabilities, cfg *oas.MCPIntrospection) map[string]string {
	if caps == nil {
		return nil
	}

	primitives := make(map[string]string)

	if cfg.ShouldDiscoverTools() {
		for _, t := range caps.Tools {
			key := "tool:" + t.Name
			vem := mcp.ToolPrefix + t.Name
			primitives[key] = vem
		}
	}

	if cfg.ShouldDiscoverResources() {
		for _, r := range caps.Resources {
			key := "resource:" + r.URI
			vem := mcp.ResourcePrefix + r.URI
			primitives[key] = vem
		}
	}

	if cfg.ShouldDiscoverPrompts() {
		for _, p := range caps.Prompts {
			key := "prompt:" + p.Name
			vem := mcp.PromptPrefix + p.Name
			primitives[key] = vem
		}
	}

	return primitives
}

// handleIntrospect validates that the API exists and is an MCP API, then runs
// an on-demand introspection cycle and returns the discovered capabilities.
func (gw *Gateway) handleIntrospect(apiID string) (any, int) {
	spec := gw.getApiSpec(apiID)
	if spec == nil {
		return apiError("API not found"), http.StatusNotFound
	}

	if !spec.IsMCP() {
		return apiError("API is not an MCP API"), http.StatusBadRequest
	}

	start := time.Now()
	result, err := gw.runIntrospection(spec)
	if err != nil {
		return apiError(fmt.Sprintf("introspection failed: %s", err.Error())), http.StatusBadGateway
	}

	return map[string]any{
		"status":       "ok",
		"durationMs":   time.Since(start).Milliseconds(),
		"capabilities": result.Capabilities,
		"partial":      result.Partial,
		"errors":       result.Errors,
	}, http.StatusOK
}

// mcpIntrospectHandler is the HTTP handler for triggering an on-demand
// introspection of an MCP API's upstream server.
func (gw *Gateway) mcpIntrospectHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	obj, code := gw.handleIntrospect(apiID)
	doJSONWrite(w, code, obj)
}
