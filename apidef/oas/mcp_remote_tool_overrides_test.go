package oas

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRemoteMCPProxyOAS(t *testing.T, upstreamURL string, primitives ...TykMCPServerPrimitive) *OAS {
	t.Helper()

	doc := newDeriveTestOAS(openapi3.NewPaths())
	doc.SetTykExtension(&XTykAPIGateway{
		Info:     Info{Name: "github"},
		Upstream: Upstream{URL: upstreamURL},
	})
	doc.SetTykMCPServerExtension(&TykMCPServer{Primitives: primitives})
	return doc
}

func toolOverride(source, name string) TykMCPServerPrimitive {
	return TykMCPServerPrimitive{Source: TykMCPServerSource{ToolName: source}, Name: name}
}

func TestTykMCPServerExtension_RemoteToolSelectorRoundTripsThroughCompaction(t *testing.T) {
	t.Parallel()

	raw := []byte(`{
		"openapi":"3.0.3",
		"info":{"title":"github","version":"1.0.0"},
		"paths":{},
		"x-tyk-api-gateway":{
			"info":{"name":"github"},
			"upstream":{"url":"https://mcp.example.com/mcp"},
			"server":{"listenPath":{"value":"/github/","strip":true}}
		},
		"x-tyk-mcp-server":{
			"primitives":[{
				"source":{"toolName":"create_issue"},
				"annotations":{"title":"Create GitHub issue","idempotentHint":false}
			}]
		}
	}`)

	var doc OAS
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.NoError(t, doc.ValidateForMCP(context.Background()))

	doc.CompactTykMCPServerExtension()
	out, err := json.Marshal(&doc)
	require.NoError(t, err)

	var stored struct {
		Server struct {
			Primitives []map[string]json.RawMessage `json:"primitives"`
		} `json:"x-tyk-mcp-server"`
	}
	require.NoError(t, json.Unmarshal(out, &stored))
	require.Len(t, stored.Server.Primitives, 1)
	assert.JSONEq(t, `{"toolName":"create_issue"}`, string(stored.Server.Primitives[0]["source"]))
	assert.JSONEq(t, `{"title":"Create GitHub issue","idempotentHint":false}`, string(stored.Server.Primitives[0]["annotations"]),
		"explicit false must be stored; unset hints must stay absent")

	var reloaded OAS
	require.NoError(t, json.Unmarshal(out, &reloaded))
	annotations := reloaded.GetTykMCPServerExtension().Primitives[0].Annotations
	require.NotNil(t, annotations.IdempotentHint)
	assert.False(t, *annotations.IdempotentHint)
	assert.Nil(t, annotations.DestructiveHint)
}

func TestTykMCPServerExtension_RemoteToolSelectorPlacement(t *testing.T) {
	t.Parallel()

	t.Run("toolName accepted on a remote MCP proxy", func(t *testing.T) {
		doc := newRemoteMCPProxyOAS(t, "https://mcp.example.com/mcp", toolOverride("delete_repo", ""))
		assert.NoError(t, doc.ValidateForMCP(context.Background()))
	})

	t.Run("toolName rejected on a REST-as-MCP proxy", func(t *testing.T) {
		doc := newRemoteMCPProxyOAS(t, AdapterLoopURL("rest-1"), toolOverride("delete_repo", ""))
		err := doc.ValidateForMCP(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "source.toolName is valid only for remote MCP proxies")
	})

	t.Run("operationId rejected on a remote MCP proxy", func(t *testing.T) {
		doc := newRemoteMCPProxyOAS(t, "https://mcp.example.com/mcp",
			TykMCPServerPrimitive{Source: TykMCPServerSource{OperationID: "deleteRepo"}})
		err := doc.ValidateForMCP(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "REST-as-MCP adapter")
	})

	t.Run("toolName combined with a REST selector rejected", func(t *testing.T) {
		doc := newRemoteMCPProxyOAS(t, "https://mcp.example.com/mcp",
			TykMCPServerPrimitive{Source: TykMCPServerSource{ToolName: "delete_repo", OperationID: "deleteRepo"}})
		err := doc.ValidateForMCP(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "REST-as-MCP adapter")
	})

	t.Run("parameters rejected on a remote MCP proxy", func(t *testing.T) {
		primitive := toolOverride("create_issue", "")
		primitive.Parameters = []TykMCPServerParameter{{Param: "repo", Name: "repository"}}
		doc := newRemoteMCPProxyOAS(t, "https://mcp.example.com/mcp", primitive)
		err := doc.ValidateForMCP(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parameters are not supported on remote MCP proxies")
	})

	t.Run("allow rejected on a remote MCP proxy", func(t *testing.T) {
		primitive := toolOverride("create_issue", "")
		primitive.Allow = boolRef(true)
		doc := newRemoteMCPProxyOAS(t, "https://mcp.example.com/mcp", primitive)
		err := doc.ValidateForMCP(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "allow is not supported on remote MCP proxies")
	})

	t.Run("missing selector rejected", func(t *testing.T) {
		doc := newRemoteMCPProxyOAS(t, "https://mcp.example.com/mcp", TykMCPServerPrimitive{Name: "x"})
		err := doc.ValidateForMCP(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "source.toolName is required")
	})

	t.Run("non-MCP API rejected", func(t *testing.T) {
		doc := newRemoteMCPProxyOAS(t, "https://mcp.example.com/mcp", toolOverride("delete_repo", ""))
		err := doc.Validate(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MCP proxies")
	})
}

func TestValidateRemoteMCPToolOverrides(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		primitives []TykMCPServerPrimitive
		wantErr    []string
	}{
		{
			name:       "invalid characters in name",
			primitives: []TykMCPServerPrimitive{toolOverride("create_issue", "create issue!")},
			wantErr:    []string{"create issue!", "use ASCII letters, digits, underscores, hyphens, and dots only"},
		},
		{
			name:       "name exceeding 128 characters",
			primitives: []TykMCPServerPrimitive{toolOverride("create_issue", strings.Repeat("a", 129))},
			wantErr:    []string{"exceeds maximum length of 128 characters"},
		},
		{
			name:       "name of exactly 128 characters",
			primitives: []TykMCPServerPrimitive{toolOverride("create_issue", strings.Repeat("a", 128))},
		},
		{
			name: "two overrides with the same final name",
			primitives: []TykMCPServerPrimitive{
				toolOverride("create_issue", "open_ticket"),
				toolOverride("create_pull_request", "open_ticket"),
			},
			wantErr: []string{`"open_ticket" is a duplicate tool name`},
		},
		{
			name: "rename onto another override's kept name",
			primitives: []TykMCPServerPrimitive{
				toolOverride("list_issues", ""),
				toolOverride("search_issues", "list_issues"),
			},
			wantErr: []string{`"list_issues" is a duplicate tool name`},
		},
		{
			name: "duplicate source tool",
			primitives: []TykMCPServerPrimitive{
				toolOverride("create_issue", "a"),
				toolOverride("create_issue", "b"),
			},
			wantErr: []string{`duplicate source.toolName "create_issue"`},
		},
		{
			name:       "source toolName with surrounding whitespace",
			primitives: []TykMCPServerPrimitive{toolOverride(" create_issue", "")},
			wantErr:    []string{`source.toolName " create_issue" is not a valid tool name`, "use ASCII letters"},
		},
		{
			name:       "source toolName with invalid characters",
			primitives: []TykMCPServerPrimitive{toolOverride("create issue", "")},
			wantErr:    []string{`source.toolName "create issue" is not a valid tool name`},
		},
		{
			name:       "source toolName over 128 characters",
			primitives: []TykMCPServerPrimitive{toolOverride(strings.Repeat("a", 129), "")},
			wantErr:    []string{"is not a valid tool name", "exceeds maximum length of 128 characters"},
		},
		{
			name: "swap and freed-name reuse",
			primitives: []TykMCPServerPrimitive{
				toolOverride("remove_repo", "delete_repo"),
				toolOverride("update_repo", "remove_repo"),
			},
		},
		{
			name: "two-way swap",
			primitives: []TykMCPServerPrimitive{
				toolOverride("a", "b"),
				toolOverride("b", "a"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ext := &TykMCPServer{Primitives: tc.primitives}
			err := ValidateRemoteMCPToolOverrides(ext)
			if len(tc.wantErr) == 0 {
				assert.NoError(t, err)

				doc := newRemoteMCPProxyOAS(t, "https://mcp.example.com/mcp", tc.primitives...)
				assert.NoError(t, doc.ValidateForMCP(context.Background()))
				return
			}
			require.Error(t, err)
			for _, want := range tc.wantErr {
				assert.Contains(t, err.Error(), want)
			}

			doc := newRemoteMCPProxyOAS(t, "https://mcp.example.com/mcp", tc.primitives...)
			err = doc.ValidateForMCP(context.Background())
			require.Error(t, err, "ValidateForMCP must surface the same error")
			assert.Contains(t, err.Error(), tc.wantErr[0])
		})
	}
}

func TestTykMCPServerExtension_NonBooleanHintIsAValidationError(t *testing.T) {
	t.Parallel()

	raw := []byte(`{
		"openapi":"3.0.3",
		"info":{"title":"github","version":"1.0.0"},
		"paths":{},
		"x-tyk-api-gateway":{
			"info":{"name":"github"},
			"upstream":{"url":"https://mcp.example.com/mcp"},
			"server":{"listenPath":{"value":"/github/","strip":true}}
		},
		"x-tyk-mcp-server":{
			"primitives":[{"source":{"toolName":"delete_repo"},"annotations":{"destructiveHint":"yes"}}]
		}
	}`)

	var doc OAS
	require.NoError(t, json.Unmarshal(raw, &doc))
	err := doc.ValidateForMCP(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "destructiveHint must be a boolean")
}
