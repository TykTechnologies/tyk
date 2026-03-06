package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/user"
)

func TestNewMCPListFilterSSEHook(t *testing.T) {
	apiID := "test-api"

	t.Run("nil session returns nil", func(t *testing.T) {
		hook := NewMCPListFilterSSEHook(apiID, nil)
		assert.Nil(t, hook)
	})

	t.Run("empty access rights returns nil", func(t *testing.T) {
		ses := &user.SessionState{
			AccessRights: map[string]user.AccessDefinition{
				apiID: {},
			},
		}
		hook := NewMCPListFilterSSEHook(apiID, ses)
		assert.Nil(t, hook)
	})

	t.Run("wrong API ID returns nil", func(t *testing.T) {
		ses := &user.SessionState{
			AccessRights: map[string]user.AccessDefinition{
				"other-api": {
					MCPAccessRights: user.MCPAccessRights{
						Tools: user.AccessControlRules{Allowed: []string{"foo"}},
					},
				},
			},
		}
		hook := NewMCPListFilterSSEHook(apiID, ses)
		assert.Nil(t, hook)
	})

	t.Run("configured rules returns hook", func(t *testing.T) {
		ses := &user.SessionState{
			AccessRights: map[string]user.AccessDefinition{
				apiID: {
					MCPAccessRights: user.MCPAccessRights{
						Tools: user.AccessControlRules{Allowed: []string{"get_weather"}},
					},
				},
			},
		}
		hook := NewMCPListFilterSSEHook(apiID, ses)
		assert.NotNil(t, hook)
	})
}

func TestMCPListFilterSSEHook_FilterEvent(t *testing.T) {
	apiID := "test-api"

	makeSession := func(tools user.AccessControlRules) *user.SessionState {
		return &user.SessionState{
			AccessRights: map[string]user.AccessDefinition{
				apiID: {
					MCPAccessRights: user.MCPAccessRights{Tools: tools},
				},
			},
		}
	}

	makeToolsListData := func(toolNames []string) string {
		tools := make([]map[string]any, 0, len(toolNames))
		for _, n := range toolNames {
			tools = append(tools, map[string]any{
				"name":        n,
				"description": "tool " + n,
			})
		}
		result := map[string]any{"tools": tools}
		resultBytes, _ := json.Marshal(result) //nolint:errcheck
		envelope := map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  json.RawMessage(resultBytes),
		}
		b, _ := json.Marshal(envelope) //nolint:errcheck
		return string(b)
	}

	extractToolNames := func(t *testing.T, data string) []string {
		t.Helper()
		var envelope mcp.JSONRPCResponse
		require.NoError(t, json.Unmarshal([]byte(data), &envelope))

		var result map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(envelope.Result, &result))

		var tools []map[string]any
		require.NoError(t, json.Unmarshal(result["tools"], &tools))

		names := make([]string, 0, len(tools))
		for _, tool := range tools {
			names = append(names, tool["name"].(string))
		}
		return names
	}

	t.Run("filters tools in SSE event by allowlist", func(t *testing.T) {
		ses := makeSession(user.AccessControlRules{
			Allowed: []string{"get_weather", "get_forecast"},
		})
		hook := NewMCPListFilterSSEHook(apiID, ses)
		require.NotNil(t, hook)

		event := &SSEEvent{
			Event: "message",
			Data:  []string{makeToolsListData([]string{"get_weather", "get_forecast", "set_alert", "delete_alert"})},
		}

		allowed, modified := hook.FilterEvent(event)
		assert.True(t, allowed)
		require.NotNil(t, modified)

		names := extractToolNames(t, strings.Join(modified.Data, "\n"))
		assert.ElementsMatch(t, []string{"get_weather", "get_forecast"}, names)
	})

	t.Run("filters tools by denylist", func(t *testing.T) {
		ses := makeSession(user.AccessControlRules{
			Blocked: []string{"set_alert", "delete_alert"},
		})
		hook := NewMCPListFilterSSEHook(apiID, ses)
		require.NotNil(t, hook)

		event := &SSEEvent{
			Data: []string{makeToolsListData([]string{"get_weather", "get_forecast", "set_alert", "delete_alert"})},
		}

		allowed, modified := hook.FilterEvent(event)
		assert.True(t, allowed)
		require.NotNil(t, modified)

		names := extractToolNames(t, strings.Join(modified.Data, "\n"))
		assert.ElementsMatch(t, []string{"get_weather", "get_forecast"}, names)
	})

	t.Run("filters tools by regex pattern", func(t *testing.T) {
		ses := makeSession(user.AccessControlRules{
			Allowed: []string{"get_.*"},
		})
		hook := NewMCPListFilterSSEHook(apiID, ses)
		require.NotNil(t, hook)

		event := &SSEEvent{
			Event: "message",
			Data:  []string{makeToolsListData([]string{"get_weather", "get_forecast", "set_alert"})},
		}

		allowed, modified := hook.FilterEvent(event)
		assert.True(t, allowed)
		require.NotNil(t, modified)

		names := extractToolNames(t, strings.Join(modified.Data, "\n"))
		assert.ElementsMatch(t, []string{"get_weather", "get_forecast"}, names)
	})

	t.Run("deny takes precedence over allow", func(t *testing.T) {
		ses := makeSession(user.AccessControlRules{
			Allowed: []string{"set_alert"},
			Blocked: []string{"set_alert"},
		})
		hook := NewMCPListFilterSSEHook(apiID, ses)
		require.NotNil(t, hook)

		event := &SSEEvent{
			Event: "message",
			Data:  []string{makeToolsListData([]string{"set_alert", "delete_alert"})},
		}

		allowed, modified := hook.FilterEvent(event)
		assert.True(t, allowed)
		require.NotNil(t, modified)

		names := extractToolNames(t, strings.Join(modified.Data, "\n"))
		assert.Empty(t, names)
	})

	t.Run("preserves pagination cursor", func(t *testing.T) {
		ses := makeSession(user.AccessControlRules{
			Allowed: []string{"get_weather"},
		})
		hook := NewMCPListFilterSSEHook(apiID, ses)

		result := map[string]any{
			"tools":      []map[string]any{{"name": "get_weather"}, {"name": "set_alert"}},
			"nextCursor": "abc123",
		}
		resultBytes, _ := json.Marshal(result) //nolint:errcheck
		envelope := map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  json.RawMessage(resultBytes),
		}
		b, _ := json.Marshal(envelope) //nolint:errcheck

		event := &SSEEvent{Data: []string{string(b)}}
		allowed, modified := hook.FilterEvent(event)
		assert.True(t, allowed)
		require.NotNil(t, modified)

		var env mcp.JSONRPCResponse
		require.NoError(t, json.Unmarshal([]byte(modified.Data[0]), &env))
		var res map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(env.Result, &res))
		assert.Contains(t, string(res["nextCursor"]), "abc123")
	})

	t.Run("passes through non-message event types", func(t *testing.T) {
		ses := makeSession(user.AccessControlRules{Allowed: []string{"get_weather"}})
		hook := NewMCPListFilterSSEHook(apiID, ses)

		event := &SSEEvent{
			Event: "error",
			Data:  []string{"upstream connection lost"},
		}

		allowed, modified := hook.FilterEvent(event)
		assert.True(t, allowed)
		assert.Nil(t, modified)
	})

	t.Run("passes through non-list JSON-RPC responses", func(t *testing.T) {
		ses := makeSession(user.AccessControlRules{Allowed: []string{"get_weather"}})
		hook := NewMCPListFilterSSEHook(apiID, ses)

		// A tools/call response has "content", not "tools"
		result := map[string]any{
			"content": []map[string]any{{"type": "text", "text": "hello"}},
		}
		resultBytes, _ := json.Marshal(result) //nolint:errcheck
		envelope := map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  json.RawMessage(resultBytes),
		}
		b, _ := json.Marshal(envelope) //nolint:errcheck

		event := &SSEEvent{
			Event: "message",
			Data:  []string{string(b)},
		}

		allowed, modified := hook.FilterEvent(event)
		assert.True(t, allowed)
		assert.Nil(t, modified) // no modification for non-list responses
	})

	t.Run("passes through error responses", func(t *testing.T) {
		ses := makeSession(user.AccessControlRules{Allowed: []string{"get_weather"}})
		hook := NewMCPListFilterSSEHook(apiID, ses)

		errObj := map[string]any{"code": -32600, "message": "invalid request"}
		errBytes, _ := json.Marshal(errObj) //nolint:errcheck
		envelope := map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"error":   json.RawMessage(errBytes),
		}
		b, _ := json.Marshal(envelope) //nolint:errcheck

		event := &SSEEvent{Data: []string{string(b)}}

		allowed, modified := hook.FilterEvent(event)
		assert.True(t, allowed)
		assert.Nil(t, modified)
	})

	t.Run("passes through empty data", func(t *testing.T) {
		ses := makeSession(user.AccessControlRules{Allowed: []string{"get_weather"}})
		hook := NewMCPListFilterSSEHook(apiID, ses)

		event := &SSEEvent{Data: []string{}}
		allowed, modified := hook.FilterEvent(event)
		assert.True(t, allowed)
		assert.Nil(t, modified)
	})

	t.Run("passes through malformed JSON", func(t *testing.T) {
		ses := makeSession(user.AccessControlRules{Allowed: []string{"get_weather"}})
		hook := NewMCPListFilterSSEHook(apiID, ses)

		event := &SSEEvent{Data: []string{`{not valid json`}}
		allowed, modified := hook.FilterEvent(event)
		assert.True(t, allowed)
		assert.Nil(t, modified)
	})

	t.Run("handles multi-line SSE data", func(t *testing.T) {
		ses := makeSession(user.AccessControlRules{
			Allowed: []string{"get_weather"},
		})
		hook := NewMCPListFilterSSEHook(apiID, ses)

		// Split JSON across multiple data: lines (valid per SSE spec)
		fullJSON := makeToolsListData([]string{"get_weather", "set_alert"})
		mid := len(fullJSON) / 2
		event := &SSEEvent{
			Event: "message",
			Data:  []string{fullJSON[:mid], fullJSON[mid:]},
		}

		allowed, modified := hook.FilterEvent(event)
		assert.True(t, allowed)
		require.NotNil(t, modified)

		names := extractToolNames(t, strings.Join(modified.Data, "\n"))
		assert.Equal(t, []string{"get_weather"}, names)
	})
}

func TestMCPListFilterSSEHook_PromptFiltering(t *testing.T) {
	apiID := "test-api"
	ses := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			apiID: {
				MCPAccessRights: user.MCPAccessRights{
					Prompts: user.AccessControlRules{Allowed: []string{"summarise"}},
				},
			},
		},
	}
	hook := NewMCPListFilterSSEHook(apiID, ses)
	require.NotNil(t, hook)

	result := map[string]any{
		"prompts": []map[string]any{
			{"name": "summarise"}, {"name": "translate"}, {"name": "greet"},
		},
	}
	resultBytes, _ := json.Marshal(result) //nolint:errcheck
	envelope := map[string]any{"jsonrpc": "2.0", "id": 1, "result": json.RawMessage(resultBytes)}
	b, _ := json.Marshal(envelope) //nolint:errcheck

	event := &SSEEvent{Data: []string{string(b)}}
	allowed, modified := hook.FilterEvent(event)
	assert.True(t, allowed)
	require.NotNil(t, modified)

	var env mcp.JSONRPCResponse
	require.NoError(t, json.Unmarshal([]byte(modified.Data[0]), &env))
	var res map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(env.Result, &res))
	var prompts []map[string]any
	require.NoError(t, json.Unmarshal(res["prompts"], &prompts))
	assert.Len(t, prompts, 1)
	assert.Equal(t, "summarise", prompts[0]["name"])
}

func TestMCPListFilterSSEHook_ResourceTemplateFiltering(t *testing.T) {
	apiID := "test-api"
	ses := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			apiID: {
				MCPAccessRights: user.MCPAccessRights{
					Resources: user.AccessControlRules{
						Blocked: []string{`db://\{schema\}/\{table\}`},
					},
				},
			},
		},
	}
	hook := NewMCPListFilterSSEHook(apiID, ses)
	require.NotNil(t, hook)

	result := map[string]any{
		"resourceTemplates": []map[string]any{
			{"uriTemplate": "file://{path}", "name": "File"},
			{"uriTemplate": "db://{schema}/{table}", "name": "DB Table"},
		},
	}
	resultBytes, _ := json.Marshal(result) //nolint:errcheck
	envelope := map[string]any{"jsonrpc": "2.0", "id": 1, "result": json.RawMessage(resultBytes)}
	b, _ := json.Marshal(envelope) //nolint:errcheck

	event := &SSEEvent{Data: []string{string(b)}}
	allowed, modified := hook.FilterEvent(event)
	assert.True(t, allowed)
	require.NotNil(t, modified)

	var env mcp.JSONRPCResponse
	require.NoError(t, json.Unmarshal([]byte(modified.Data[0]), &env))
	var res map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(env.Result, &res))
	var templates []map[string]any
	require.NoError(t, json.Unmarshal(res["resourceTemplates"], &templates))
	assert.Len(t, templates, 1)
	assert.Equal(t, "file://{path}", templates[0]["uriTemplate"])
}

// ── Benchmarks ──────────────────────────────────────────────────────────────

// generateSSEToolsEvent builds an SSE event carrying a tools/list JSON-RPC response
// with n tools named "tool_0" … "tool_{n-1}".
func generateSSEToolsEvent(n int) *SSEEvent {
	tools := make([]map[string]any, n)
	for i := range n {
		tools[i] = map[string]any{
			"name":        fmt.Sprintf("tool_%d", i),
			"description": fmt.Sprintf("Tool number %d", i),
		}
	}
	result := map[string]any{"tools": tools}
	resultBytes, _ := json.Marshal(result) //nolint:errcheck
	envelope := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result":  json.RawMessage(resultBytes),
	}
	b, _ := json.Marshal(envelope) //nolint:errcheck
	return &SSEEvent{Event: "message", Data: []string{string(b)}}
}

// benchmarkSSEHook measures FilterEvent alone (no SSETap overhead).
func benchmarkSSEHook(b *testing.B, numTools int, rules user.AccessControlRules) {
	b.Helper()
	apiID := "bench-api"
	ses := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			apiID: {
				MCPAccessRights: user.MCPAccessRights{Tools: rules},
			},
		},
	}
	hook := NewMCPListFilterSSEHook(apiID, ses)
	event := generateSSEToolsEvent(numTools)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		hook.FilterEvent(event)
	}
}

func BenchmarkSSEHook_100Tools(b *testing.B) {
	allowed := make([]string, 10)
	for i := range 10 {
		allowed[i] = fmt.Sprintf("tool_%d", i)
	}
	benchmarkSSEHook(b, 100, user.AccessControlRules{Allowed: allowed})
}

func BenchmarkSSEHook_1000Tools(b *testing.B) {
	allowed := make([]string, 10)
	for i := range 10 {
		allowed[i] = fmt.Sprintf("tool_%d", i)
	}
	benchmarkSSEHook(b, 1000, user.AccessControlRules{Allowed: allowed})
}

func BenchmarkSSEHook_100Tools_Regex(b *testing.B) {
	benchmarkSSEHook(b, 100, user.AccessControlRules{
		Allowed: []string{"tool_[0-9]", "tool_1[0-9]"},
	})
}

func BenchmarkSSEHook_1000Tools_Regex(b *testing.B) {
	benchmarkSSEHook(b, 1000, user.AccessControlRules{
		Allowed: []string{"tool_[0-9]", "tool_1[0-9]"},
	})
}

func BenchmarkSSEHook_NonListEvent(b *testing.B) {
	apiID := "bench-api"
	ses := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			apiID: {
				MCPAccessRights: user.MCPAccessRights{
					Tools: user.AccessControlRules{Allowed: []string{"tool_0"}},
				},
			},
		},
	}
	hook := NewMCPListFilterSSEHook(apiID, ses)
	// A tools/call result — should pass through without parsing.
	result := map[string]any{"content": []map[string]any{{"type": "text", "text": "hello"}}}
	resultBytes, _ := json.Marshal(result) //nolint:errcheck
	envelope := map[string]any{"jsonrpc": "2.0", "id": 1, "result": json.RawMessage(resultBytes)}
	data, _ := json.Marshal(envelope) //nolint:errcheck
	event := &SSEEvent{Event: "message", Data: []string{string(data)}}

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		hook.FilterEvent(event)
	}
}

// benchmarkSSETapEndToEnd measures the full SSETap pipeline: parsing SSE bytes
// from an io.Reader, running the hook, and reading filtered output.
func benchmarkSSETapEndToEnd(b *testing.B, numTools int, rules user.AccessControlRules) {
	b.Helper()
	apiID := "bench-api"
	ses := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			apiID: {
				MCPAccessRights: user.MCPAccessRights{Tools: rules},
			},
		},
	}
	hook := NewMCPListFilterSSEHook(apiID, ses)

	// Build the raw SSE bytes as the upstream would send them.
	event := generateSSEToolsEvent(numTools)
	raw := serializeSSEEvent(event)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		reader := io.NopCloser(bytes.NewReader(raw))
		tap := NewSSETap(reader, hook)
		io.ReadAll(tap) //nolint:errcheck
		tap.Close()
	}
}

func BenchmarkSSETap_E2E_100Tools(b *testing.B) {
	allowed := make([]string, 10)
	for i := range 10 {
		allowed[i] = fmt.Sprintf("tool_%d", i)
	}
	benchmarkSSETapEndToEnd(b, 100, user.AccessControlRules{Allowed: allowed})
}

func BenchmarkSSETap_E2E_1000Tools(b *testing.B) {
	allowed := make([]string, 10)
	for i := range 10 {
		allowed[i] = fmt.Sprintf("tool_%d", i)
	}
	benchmarkSSETapEndToEnd(b, 1000, user.AccessControlRules{Allowed: allowed})
}

func BenchmarkSSETap_E2E_1000Tools_Regex(b *testing.B) {
	benchmarkSSETapEndToEnd(b, 1000, user.AccessControlRules{
		Allowed: []string{"tool_[0-9]", "tool_1[0-9]"},
	})
}

func BenchmarkSSETap_E2E_NoRules(b *testing.B) {
	// No hook — pure SSETap passthrough for comparison.
	event := generateSSEToolsEvent(1000)
	raw := serializeSSEEvent(event)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		reader := io.NopCloser(bytes.NewReader(raw))
		tap := NewSSETap(reader) // no hooks
		io.ReadAll(tap)          //nolint:errcheck
		tap.Close()
	}
}
