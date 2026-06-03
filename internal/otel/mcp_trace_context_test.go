package otel

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/mcp"
)

// The default read_sources is the spec-canonical [header, body@params._meta]:
// header preserves today's header-wins behaviour, body@params._meta is the
// MCP-spec location. Omitting the block must materialise this default so an
// operator dumping the resolved config sees exactly what Tyk will read.
func TestMCPTraceContext_SetDefaults_OmittedBlockGetsCanonicalSources(t *testing.T) {
	c := OpenTelemetry{}
	c.SetDefaults()

	require.Len(t, c.MCPTraceContext.ReadSources, 2)
	assert.Equal(t, MCPTraceChannelHeader, c.MCPTraceContext.ReadSources[0].Channel)
	assert.Empty(t, c.MCPTraceContext.ReadSources[0].Path)
	assert.Equal(t, MCPTraceChannelBody, c.MCPTraceContext.ReadSources[1].Channel)
	assert.Equal(t, "params._meta", c.MCPTraceContext.ReadSources[1].Path)
}

// An operator-configured list is an explicit override and must survive
// SetDefaults untouched — the default only fills an omitted block.
func TestMCPTraceContext_SetDefaults_ExplicitSourcesPreserved(t *testing.T) {
	c := OpenTelemetry{
		MCPTraceContext: MCPTraceContextConfig{
			ReadSources: []MCPTraceSource{
				{Channel: MCPTraceChannelBody, Path: "meta"},
			},
		},
	}
	c.SetDefaults()

	require.Len(t, c.MCPTraceContext.ReadSources, 1)
	assert.Equal(t, MCPTraceChannelBody, c.MCPTraceContext.ReadSources[0].Channel)
	assert.Equal(t, "meta", c.MCPTraceContext.ReadSources[0].Path)
}

// Span carries the MCP method (always) and tool (only when a primitive
// resolved), per GenAI/MCP semantic conventions, plus the trace_source label.
func TestMCPSpanAttributes(t *testing.T) {
	keys := func(attrs []SpanAttribute) map[string]string {
		m := map[string]string{}
		for _, a := range attrs {
			m[string(a.Key)] = a.Value.AsString()
		}
		return m
	}

	t.Run("method, tool and trace_source all stamped", func(t *testing.T) {
		got := keys(MCPSpanAttributes("tools/call", mcp.PrimitiveTypeTool, "sendMail", "meta"))
		assert.Equal(t, "tools/call", got["mcp.method.name"])
		assert.Equal(t, "sendMail", got["mcp.tool.name"])
		assert.Equal(t, "meta", got["mcp.trace_source"])
	})

	t.Run("primitive name keyed by type — resources and prompts, not just tools", func(t *testing.T) {
		res := keys(MCPSpanAttributes("resources/read", mcp.PrimitiveTypeResource, "user-profile", "meta"))
		assert.Equal(t, "user-profile", res["mcp.resource.name"])
		_, hasTool := res["mcp.tool.name"]
		assert.False(t, hasTool, "a resource must not be labelled mcp.tool.name")

		prm := keys(MCPSpanAttributes("prompts/get", mcp.PrimitiveTypePrompt, "code-review", "meta"))
		assert.Equal(t, "code-review", prm["mcp.prompt.name"])
	})

	t.Run("primitive name omitted when none resolved", func(t *testing.T) {
		got := keys(MCPSpanAttributes("tools/call", mcp.PrimitiveTypeTool, "", "header"))
		assert.Equal(t, "tools/call", got["mcp.method.name"])
		_, hasTool := got["mcp.tool.name"]
		assert.False(t, hasTool, "primitive name must be omitted when none resolved")
	})
}

// The block lives at opentelemetry.mcp_trace_context.read_sources, alongside
// the existing traces/metrics extensions.
func TestMCPTraceContext_JSONShape(t *testing.T) {
	raw := []byte(`{"mcp_trace_context":{"read_sources":[{"channel":"header"},{"channel":"body","path":"params._meta"}]}}`)
	var c OpenTelemetry
	require.NoError(t, json.Unmarshal(raw, &c))

	require.Len(t, c.MCPTraceContext.ReadSources, 2)
	assert.Equal(t, "header", c.MCPTraceContext.ReadSources[0].Channel)
	assert.Equal(t, "body", c.MCPTraceContext.ReadSources[1].Channel)
	assert.Equal(t, "params._meta", c.MCPTraceContext.ReadSources[1].Path)
}
