//go:build ee || dev

package oauth2tokenexchange

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/mcp"
)

func activePrimitive(audience string) *oas.MCPPrimitive {
	enabled := true
	p := &oas.MCPPrimitive{}
	p.Exchange = &oas.OAuth2Exchange{Enabled: &enabled, Audience: audience}
	return p
}

func TestFindActivePrimitive_ToolLookup(t *testing.T) {
	mw := &oas.Middleware{
		McpTools: oas.MCPPrimitives{"search": activePrimitive("https://tool-api")},
	}
	got := findActivePrimitive(mw, "search", mcp.PrimitiveTypeTool)
	require.NotNil(t, got)
	assert.Equal(t, "https://tool-api", got.Exchange.Audience)
}

func TestFindActivePrimitive_PromptLookup(t *testing.T) {
	mw := &oas.Middleware{
		McpPrompts: oas.MCPPrimitives{"search": activePrimitive("https://prompt-api")},
	}
	got := findActivePrimitive(mw, "search", mcp.PrimitiveTypePrompt)
	require.NotNil(t, got)
	assert.Equal(t, "https://prompt-api", got.Exchange.Audience)
}

// TestFindActivePrimitive_SameNameCollision is the regression guard for the bug
// Andrei identified: a tool and a prompt sharing the same name must not collide.
// Querying by type "prompt" must return nil when only the tool has active exchange.
func TestFindActivePrimitive_SameNameCollision(t *testing.T) {
	mw := &oas.Middleware{
		McpTools:   oas.MCPPrimitives{"search": activePrimitive("https://tool-api")},
		McpPrompts: oas.MCPPrimitives{"search": &oas.MCPPrimitive{}}, // no active exchange
	}

	tool := findActivePrimitive(mw, "search", mcp.PrimitiveTypeTool)
	require.NotNil(t, tool, "tool lookup must return the tool primitive")

	prompt := findActivePrimitive(mw, "search", mcp.PrimitiveTypePrompt)
	assert.Nil(t, prompt, "prompt lookup must not return the tool primitive")
}

func TestFindActivePrimitive_BothActive_TypeSelects(t *testing.T) {
	mw := &oas.Middleware{
		McpTools:   oas.MCPPrimitives{"search": activePrimitive("https://tool-api")},
		McpPrompts: oas.MCPPrimitives{"search": activePrimitive("https://prompt-api")},
	}

	tool := findActivePrimitive(mw, "search", mcp.PrimitiveTypeTool)
	require.NotNil(t, tool)
	assert.Equal(t, "https://tool-api", tool.Exchange.Audience)

	prompt := findActivePrimitive(mw, "search", mcp.PrimitiveTypePrompt)
	require.NotNil(t, prompt)
	assert.Equal(t, "https://prompt-api", prompt.Exchange.Audience)
}

func TestFindActivePrimitive_UnknownType_FallbackSearchesAll(t *testing.T) {
	mw := &oas.Middleware{
		McpTools: oas.MCPPrimitives{"search": activePrimitive("https://tool-api")},
	}
	got := findActivePrimitive(mw, "search", "")
	require.NotNil(t, got, "unknown type falls back to searching all maps")
}
