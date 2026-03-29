package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/mcp/client"
)

func boolPtr(b bool) *bool { return &b }

func TestBuildDiscoveredPrimitives(t *testing.T) {
	t.Run("nil capabilities returns nil", func(t *testing.T) {
		cfg := &oas.MCPIntrospection{}
		got := buildDiscoveredPrimitives(nil, cfg)
		if got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
	})

	t.Run("empty capabilities returns empty map", func(t *testing.T) {
		caps := &client.ServerCapabilities{}
		cfg := &oas.MCPIntrospection{}
		got := buildDiscoveredPrimitives(caps, cfg)
		if got == nil {
			t.Fatal("expected non-nil map")
		}
		if len(got) != 0 {
			t.Fatalf("expected empty map, got %d entries", len(got))
		}
	})

	t.Run("all primitive types discovered", func(t *testing.T) {
		caps := &client.ServerCapabilities{
			Tools: []client.ToolInfo{
				{Name: "get-weather"},
				{Name: "search"},
			},
			Resources: []client.ResourceInfo{
				{URI: "file:///data/config.json"},
			},
			Prompts: []client.PromptInfo{
				{Name: "code-review"},
			},
		}
		cfg := &oas.MCPIntrospection{}

		got := buildDiscoveredPrimitives(caps, cfg)

		if len(got) != 4 {
			t.Fatalf("expected 4 entries, got %d: %v", len(got), got)
		}

		wantEntries := map[string]string{
			"tool:get-weather":                  "/mcp-tool:get-weather",
			"tool:search":                       "/mcp-tool:search",
			"resource:file:///data/config.json": "/mcp-resource:file:///data/config.json",
			"prompt:code-review":                "/mcp-prompt:code-review",
		}
		for key, wantVal := range wantEntries {
			if gotVal, ok := got[key]; !ok {
				t.Errorf("missing key %q", key)
			} else if gotVal != wantVal {
				t.Errorf("key %q: got %q, want %q", key, gotVal, wantVal)
			}
		}
	})

	t.Run("DiscoverTools false excludes tools", func(t *testing.T) {
		caps := &client.ServerCapabilities{
			Tools: []client.ToolInfo{
				{Name: "get-weather"},
			},
			Resources: []client.ResourceInfo{
				{URI: "file:///data"},
			},
		}
		cfg := &oas.MCPIntrospection{
			DiscoverTools: boolPtr(false),
		}

		got := buildDiscoveredPrimitives(caps, cfg)

		if _, ok := got["tool:get-weather"]; ok {
			t.Error("tools should be excluded when DiscoverTools is false")
		}
		if _, ok := got["resource:file:///data"]; !ok {
			t.Error("resources should still be included")
		}
	})

	t.Run("DiscoverResources false excludes resources", func(t *testing.T) {
		caps := &client.ServerCapabilities{
			Tools: []client.ToolInfo{
				{Name: "get-weather"},
			},
			Resources: []client.ResourceInfo{
				{URI: "file:///data"},
			},
		}
		cfg := &oas.MCPIntrospection{
			DiscoverResources: boolPtr(false),
		}

		got := buildDiscoveredPrimitives(caps, cfg)

		if _, ok := got["resource:file:///data"]; ok {
			t.Error("resources should be excluded when DiscoverResources is false")
		}
		if _, ok := got["tool:get-weather"]; !ok {
			t.Error("tools should still be included")
		}
	})

	t.Run("DiscoverPrompts false excludes prompts", func(t *testing.T) {
		caps := &client.ServerCapabilities{
			Prompts: []client.PromptInfo{
				{Name: "code-review"},
			},
			Tools: []client.ToolInfo{
				{Name: "search"},
			},
		}
		cfg := &oas.MCPIntrospection{
			DiscoverPrompts: boolPtr(false),
		}

		got := buildDiscoveredPrimitives(caps, cfg)

		if _, ok := got["prompt:code-review"]; ok {
			t.Error("prompts should be excluded when DiscoverPrompts is false")
		}
		if _, ok := got["tool:search"]; !ok {
			t.Error("tools should still be included")
		}
	})

	t.Run("all discovery disabled returns empty map", func(t *testing.T) {
		caps := &client.ServerCapabilities{
			Tools:     []client.ToolInfo{{Name: "t1"}},
			Resources: []client.ResourceInfo{{URI: "r1"}},
			Prompts:   []client.PromptInfo{{Name: "p1"}},
		}
		cfg := &oas.MCPIntrospection{
			DiscoverTools:     boolPtr(false),
			DiscoverResources: boolPtr(false),
			DiscoverPrompts:   boolPtr(false),
		}

		got := buildDiscoveredPrimitives(caps, cfg)

		if len(got) != 0 {
			t.Fatalf("expected empty map, got %d entries: %v", len(got), got)
		}
	})
}

func TestGetIntrospectionConfig(t *testing.T) {
	t.Run("nil spec returns nil", func(t *testing.T) {
		got := getIntrospectionConfig(nil)
		if got != nil {
			t.Fatalf("expected nil, got %+v", got)
		}
	})

	t.Run("spec without OAS extension returns nil", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{},
			OAS:           oas.OAS{},
		}
		got := getIntrospectionConfig(spec)
		if got != nil {
			t.Fatalf("expected nil, got %+v", got)
		}
	})

	t.Run("spec with extension but no introspection returns nil", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{},
			OAS:           oas.OAS{},
		}
		spec.OAS.SetTykExtension(&oas.XTykAPIGateway{
			Server: oas.Server{},
		})

		got := getIntrospectionConfig(spec)
		if got != nil {
			t.Fatalf("expected nil, got %+v", got)
		}
	})

	t.Run("spec with introspection config returns it", func(t *testing.T) {
		introCfg := &oas.MCPIntrospection{
			Enabled: true,
			Timeout: "30s",
		}
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{},
			OAS:           oas.OAS{},
		}
		spec.OAS.SetTykExtension(&oas.XTykAPIGateway{
			Server: oas.Server{
				Introspection: introCfg,
			},
		})

		got := getIntrospectionConfig(spec)
		if got == nil {
			t.Fatal("expected non-nil config")
		}
		if !got.Enabled {
			t.Error("expected Enabled to be true")
		}
		if got.Timeout != "30s" {
			t.Errorf("expected Timeout %q, got %q", "30s", got.Timeout)
		}
	})
}

func TestMCPIntrospectionDefaults(t *testing.T) {
	t.Run("GetTimeout returns 10s when empty", func(t *testing.T) {
		cfg := &oas.MCPIntrospection{}
		if got := cfg.GetTimeout(); got != "10s" {
			t.Errorf("expected %q, got %q", "10s", got)
		}
	})

	t.Run("GetTimeout returns custom value when set", func(t *testing.T) {
		cfg := &oas.MCPIntrospection{Timeout: "30s"}
		if got := cfg.GetTimeout(); got != "30s" {
			t.Errorf("expected %q, got %q", "30s", got)
		}
	})

	t.Run("GetTimeout on nil receiver returns 10s", func(t *testing.T) {
		var cfg *oas.MCPIntrospection
		if got := cfg.GetTimeout(); got != "10s" {
			t.Errorf("expected %q, got %q", "10s", got)
		}
	})

	t.Run("ShouldDiscoverTools defaults to true", func(t *testing.T) {
		cfg := &oas.MCPIntrospection{}
		if !cfg.ShouldDiscoverTools() {
			t.Error("expected ShouldDiscoverTools to default to true")
		}
	})

	t.Run("ShouldDiscoverTools returns false when set", func(t *testing.T) {
		cfg := &oas.MCPIntrospection{DiscoverTools: boolPtr(false)}
		if cfg.ShouldDiscoverTools() {
			t.Error("expected ShouldDiscoverTools to be false")
		}
	})

	t.Run("ShouldDiscoverTools on nil receiver returns true", func(t *testing.T) {
		var cfg *oas.MCPIntrospection
		if !cfg.ShouldDiscoverTools() {
			t.Error("expected ShouldDiscoverTools to default to true on nil receiver")
		}
	})

	t.Run("ShouldDiscoverResources defaults to true", func(t *testing.T) {
		cfg := &oas.MCPIntrospection{}
		if !cfg.ShouldDiscoverResources() {
			t.Error("expected ShouldDiscoverResources to default to true")
		}
	})

	t.Run("ShouldDiscoverResources returns false when set", func(t *testing.T) {
		cfg := &oas.MCPIntrospection{DiscoverResources: boolPtr(false)}
		if cfg.ShouldDiscoverResources() {
			t.Error("expected ShouldDiscoverResources to be false")
		}
	})

	t.Run("ShouldDiscoverResources on nil receiver returns true", func(t *testing.T) {
		var cfg *oas.MCPIntrospection
		if !cfg.ShouldDiscoverResources() {
			t.Error("expected ShouldDiscoverResources to default to true on nil receiver")
		}
	})

	t.Run("ShouldDiscoverPrompts defaults to true", func(t *testing.T) {
		cfg := &oas.MCPIntrospection{}
		if !cfg.ShouldDiscoverPrompts() {
			t.Error("expected ShouldDiscoverPrompts to default to true")
		}
	})

	t.Run("ShouldDiscoverPrompts returns false when set", func(t *testing.T) {
		cfg := &oas.MCPIntrospection{DiscoverPrompts: boolPtr(false)}
		if cfg.ShouldDiscoverPrompts() {
			t.Error("expected ShouldDiscoverPrompts to be false")
		}
	})

	t.Run("ShouldDiscoverPrompts on nil receiver returns true", func(t *testing.T) {
		var cfg *oas.MCPIntrospection
		if !cfg.ShouldDiscoverPrompts() {
			t.Error("expected ShouldDiscoverPrompts to default to true on nil receiver")
		}
	})
}

func TestPopulateMCPPrimitivesMap_MergesDiscovered(t *testing.T) {
	t.Run("discovered primitives are loaded into MCPPrimitives", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				ApplicationProtocol: apidef.AppProtocolMCP,
			},
			OAS: oas.OAS{},
		}
		spec.OAS.SetTykExtension(&oas.XTykAPIGateway{
			Middleware: &oas.Middleware{},
		})
		spec.DiscoveredMCPPrimitives = map[string]string{
			"tool:discovered-tool":     "/mcp-tool:discovered-tool",
			"resource:file:///data":    "/mcp-resource:file:///data",
			"prompt:discovered-prompt": "/mcp-prompt:discovered-prompt",
		}

		loader := APIDefinitionLoader{}
		loader.populateMCPPrimitivesMap(spec)

		if len(spec.MCPPrimitives) != 3 {
			t.Fatalf("expected 3 entries, got %d: %v", len(spec.MCPPrimitives), spec.MCPPrimitives)
		}
		for key, wantVal := range spec.DiscoveredMCPPrimitives {
			if gotVal := spec.MCPPrimitives[key]; gotVal != wantVal {
				t.Errorf("key %q: got %q, want %q", key, gotVal, wantVal)
			}
		}
	})

	t.Run("manual config overwrites discovered for overlapping keys", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				ApplicationProtocol: apidef.AppProtocolMCP,
			},
			OAS: oas.OAS{},
		}
		spec.OAS.SetTykExtension(&oas.XTykAPIGateway{
			Middleware: &oas.Middleware{
				McpTools: oas.MCPPrimitives{
					"overlapping-tool": &oas.MCPPrimitive{},
				},
			},
		})
		spec.DiscoveredMCPPrimitives = map[string]string{
			"tool:overlapping-tool": "/mcp-tool:overlapping-tool-discovered",
			"tool:only-discovered":  "/mcp-tool:only-discovered",
		}

		loader := APIDefinitionLoader{}
		loader.populateMCPPrimitivesMap(spec)

		// The discovered-only tool should be present.
		if got := spec.MCPPrimitives["tool:only-discovered"]; got != "/mcp-tool:only-discovered" {
			t.Errorf("discovered-only tool: got %q, want %q", got, "/mcp-tool:only-discovered")
		}

		// The overlapping tool should have the manual (overwritten) value.
		if got := spec.MCPPrimitives["tool:overlapping-tool"]; got != "/mcp-tool:overlapping-tool" {
			t.Errorf("overlapping tool: got %q, want %q (manual should win)", got, "/mcp-tool:overlapping-tool")
		}
	})

	t.Run("manual tools resources and prompts all overlay discovered", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				ApplicationProtocol: apidef.AppProtocolMCP,
			},
			OAS: oas.OAS{},
		}
		spec.OAS.SetTykExtension(&oas.XTykAPIGateway{
			Middleware: &oas.Middleware{
				McpTools: oas.MCPPrimitives{
					"manual-tool": &oas.MCPPrimitive{},
				},
				McpResources: oas.MCPPrimitives{
					"file:///manual": &oas.MCPPrimitive{},
				},
				McpPrompts: oas.MCPPrimitives{
					"manual-prompt": &oas.MCPPrimitive{},
				},
			},
		})
		spec.DiscoveredMCPPrimitives = map[string]string{
			"tool:discovered-tool":     "/mcp-tool:discovered-tool",
			"resource:file:///disc":    "/mcp-resource:file:///disc",
			"prompt:discovered-prompt": "/mcp-prompt:discovered-prompt",
		}

		loader := APIDefinitionLoader{}
		loader.populateMCPPrimitivesMap(spec)

		// 3 discovered + 3 manual = 6 total (no overlap in this case).
		if len(spec.MCPPrimitives) != 6 {
			t.Fatalf("expected 6 entries, got %d: %v", len(spec.MCPPrimitives), spec.MCPPrimitives)
		}

		wantEntries := map[string]string{
			"tool:discovered-tool":     "/mcp-tool:discovered-tool",
			"tool:manual-tool":         "/mcp-tool:manual-tool",
			"resource:file:///disc":    "/mcp-resource:file:///disc",
			"resource:file:///manual":  "/mcp-resource:file:///manual",
			"prompt:discovered-prompt": "/mcp-prompt:discovered-prompt",
			"prompt:manual-prompt":     "/mcp-prompt:manual-prompt",
		}
		for key, wantVal := range wantEntries {
			if gotVal := spec.MCPPrimitives[key]; gotVal != wantVal {
				t.Errorf("key %q: got %q, want %q", key, gotVal, wantVal)
			}
		}
	})

	t.Run("no discovered primitives only manual", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				ApplicationProtocol: apidef.AppProtocolMCP,
			},
			OAS: oas.OAS{},
		}
		spec.OAS.SetTykExtension(&oas.XTykAPIGateway{
			Middleware: &oas.Middleware{
				McpTools: oas.MCPPrimitives{
					"manual-tool": &oas.MCPPrimitive{},
				},
			},
		})
		// No discovered primitives set.

		loader := APIDefinitionLoader{}
		loader.populateMCPPrimitivesMap(spec)

		if len(spec.MCPPrimitives) != 1 {
			t.Fatalf("expected 1 entry, got %d: %v", len(spec.MCPPrimitives), spec.MCPPrimitives)
		}
		if got := spec.MCPPrimitives["tool:manual-tool"]; got != "/mcp-tool:manual-tool" {
			t.Errorf("manual tool: got %q, want %q", got, "/mcp-tool:manual-tool")
		}
	})
}

func TestRunIntrospection_NoConfig(t *testing.T) {
	gw := &Gateway{}
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{},
	}

	_, err := gw.runIntrospection(spec)
	if err == nil {
		t.Fatal("expected error for spec with no introspection config")
	}
	if got := err.Error(); got == "" {
		t.Error("expected non-empty error message")
	}
}

func TestRunIntrospection_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			ID     *int64 `json:"id"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		if req.ID == nil {
			w.WriteHeader(http.StatusOK)
			return
		}

		var result any
		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "test")
			result = map[string]any{
				"protocolVersion": "2025-03-26",
				"capabilities":    map[string]any{},
				"serverInfo":      map[string]any{"name": "test", "version": "1.0"},
			}
		case "tools/list":
			result = map[string]any{"tools": []map[string]any{{"name": "tool1"}}}
		case "resources/list":
			result = map[string]any{"resources": []any{}}
		case "prompts/list":
			result = map[string]any{"prompts": []any{}}
		}

		resultJSON, _ := json.Marshal(result)
		resp := map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": json.RawMessage(resultJSON)}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	gw := &Gateway{}
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{},
		OAS:           oas.OAS{},
	}
	ext := &oas.XTykAPIGateway{
		Upstream: oas.Upstream{URL: srv.URL},
		Server: oas.Server{
			Introspection: &oas.MCPIntrospection{
				Enabled: true,
				Timeout: "5s",
			},
		},
	}
	spec.OAS.SetTykExtension(ext)

	result, err := gw.runIntrospection(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result.Capabilities.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(result.Capabilities.Tools))
	}
	if result.Capabilities.Tools[0].Name != "tool1" {
		t.Errorf("expected tool name 'tool1', got %q", result.Capabilities.Tools[0].Name)
	}
}

func TestHandleIntrospect_NotFound(t *testing.T) {
	gw := &Gateway{}
	_, code := gw.handleIntrospect("nonexistent")
	if code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", code)
	}
}
