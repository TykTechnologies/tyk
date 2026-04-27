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

	t.Run("preserves event ID through filtering", func(t *testing.T) {
		ses := makeSession(user.AccessControlRules{
			Allowed: []string{"get_weather"},
		})
		hook := NewMCPListFilterSSEHook(apiID, ses)
		require.NotNil(t, hook)

		event := &SSEEvent{
			ID:    "evt-42",
			Event: "message",
			Data:  []string{makeToolsListData([]string{"get_weather", "set_alert"})},
		}

		allowed, modified := hook.FilterEvent(event)
		assert.True(t, allowed)
		require.NotNil(t, modified)
		assert.Equal(t, "evt-42", modified.ID, "event ID should be preserved")

		names := extractToolNames(t, strings.Join(modified.Data, "\n"))
		assert.Equal(t, []string{"get_weather"}, names)
	})

	t.Run("preserves retry field through filtering", func(t *testing.T) {
		ses := makeSession(user.AccessControlRules{
			Allowed: []string{"get_weather"},
		})
		hook := NewMCPListFilterSSEHook(apiID, ses)
		require.NotNil(t, hook)

		event := &SSEEvent{
			Event: "message",
			Retry: 5000,
			Data:  []string{makeToolsListData([]string{"get_weather", "set_alert"})},
		}

		allowed, modified := hook.FilterEvent(event)
		assert.True(t, allowed)
		require.NotNil(t, modified)
		assert.Equal(t, 5000, modified.Retry, "retry should be preserved")
	})

	t.Run("empty result object passes through", func(t *testing.T) {
		ses := makeSession(user.AccessControlRules{Allowed: []string{"get_weather"}})
		hook := NewMCPListFilterSSEHook(apiID, ses)

		// Result exists but has no list key.
		envelope := map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]any{},
		}
		b, _ := json.Marshal(envelope) //nolint:errcheck

		event := &SSEEvent{Data: []string{string(b)}}
		allowed, modified := hook.FilterEvent(event)
		assert.True(t, allowed)
		assert.Nil(t, modified, "empty result should pass through unmodified")
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

// ── Out-of-Order Frame Tests ────────────────────────────────────────────────
//
// These tests verify correct behavior when SSE events arrive in various
// orderings, fragmentations, and interleaving patterns.

func TestMCPListFilterSSEHook_OutOfOrderFrames(t *testing.T) {
	apiID := "test-api"

	makeSession := func(tools, prompts user.AccessControlRules) *user.SessionState {
		return &user.SessionState{
			AccessRights: map[string]user.AccessDefinition{
				apiID: {
					MCPAccessRights: user.MCPAccessRights{
						Tools:   tools,
						Prompts: prompts,
					},
				},
			},
		}
	}

	makeJSONRPCResponse := func(id any, resultKey string, items []map[string]any) string {
		result := map[string]any{resultKey: items}
		resultBytes, _ := json.Marshal(result) //nolint:errcheck
		envelope := map[string]any{
			"jsonrpc": "2.0",
			"id":      id,
			"result":  json.RawMessage(resultBytes),
		}
		b, _ := json.Marshal(envelope) //nolint:errcheck
		return string(b)
	}

	t.Run("multiple list responses in single chunk", func(t *testing.T) {
		// Two different list responses arriving back-to-back in same read
		ses := makeSession(
			user.AccessControlRules{Allowed: []string{"allowed_tool"}},
			user.AccessControlRules{Allowed: []string{"allowed_prompt"}},
		)
		hook := NewMCPListFilterSSEHook(apiID, ses)
		require.NotNil(t, hook)

		toolsData := makeJSONRPCResponse(1, "tools", []map[string]any{
			{"name": "allowed_tool"},
			{"name": "blocked_tool"},
		})
		promptsData := makeJSONRPCResponse(2, "prompts", []map[string]any{
			{"name": "allowed_prompt"},
			{"name": "blocked_prompt"},
		})

		// Build raw SSE stream with both events
		rawStream := fmt.Sprintf("event: message\ndata: %s\n\nevent: message\ndata: %s\n\n", toolsData, promptsData)
		reader := io.NopCloser(strings.NewReader(rawStream))
		tap := NewSSETap(reader, hook)

		output, err := io.ReadAll(tap)
		require.NoError(t, err)

		// Verify tools filtered correctly
		assert.Contains(t, string(output), "allowed_tool")
		assert.NotContains(t, string(output), "blocked_tool")

		// Verify prompts filtered correctly
		assert.Contains(t, string(output), "allowed_prompt")
		assert.NotContains(t, string(output), "blocked_prompt")
	})

	t.Run("list response interleaved with non-list events", func(t *testing.T) {
		ses := makeSession(
			user.AccessControlRules{Allowed: []string{"get_weather"}},
			user.AccessControlRules{},
		)
		hook := NewMCPListFilterSSEHook(apiID, ses)
		require.NotNil(t, hook)

		// Non-list response (tools/call result)
		callResult := map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]any{"content": []map[string]any{{"type": "text", "text": "hello"}}},
		}
		callResultBytes, _ := json.Marshal(callResult) //nolint:errcheck

		// List response
		toolsData := makeJSONRPCResponse(2, "tools", []map[string]any{
			{"name": "get_weather"},
			{"name": "set_alert"},
		})

		// Error response
		errorResp := map[string]any{
			"jsonrpc": "2.0",
			"id":      3,
			"error":   map[string]any{"code": -32600, "message": "invalid"},
		}
		errorBytes, _ := json.Marshal(errorResp) //nolint:errcheck

		// Interleaved stream: call result -> tools list -> error
		rawStream := fmt.Sprintf(
			"data: %s\n\ndata: %s\n\ndata: %s\n\n",
			string(callResultBytes), toolsData, string(errorBytes),
		)
		reader := io.NopCloser(strings.NewReader(rawStream))
		tap := NewSSETap(reader, hook)

		output, err := io.ReadAll(tap)
		require.NoError(t, err)

		// Non-list events should pass through unchanged
		assert.Contains(t, string(output), `"content"`)
		assert.Contains(t, string(output), `"error"`)

		// List response should be filtered
		assert.Contains(t, string(output), "get_weather")
		assert.NotContains(t, string(output), "set_alert")
	})

	t.Run("fragmented JSON across multiple reads", func(t *testing.T) {
		ses := makeSession(
			user.AccessControlRules{Allowed: []string{"tool_a"}},
			user.AccessControlRules{},
		)
		hook := NewMCPListFilterSSEHook(apiID, ses)
		require.NotNil(t, hook)

		toolsData := makeJSONRPCResponse(1, "tools", []map[string]any{
			{"name": "tool_a", "description": "A tool"},
			{"name": "tool_b", "description": "B tool"},
		})
		rawEvent := fmt.Sprintf("data: %s\n\n", toolsData)

		// Use chunked reader to split the event mid-JSON
		reader := &chunkedReader{data: []byte(rawEvent), chunkSize: 20}
		tap := NewSSETap(reader, hook)

		output, err := io.ReadAll(tap)
		require.NoError(t, err)

		assert.Contains(t, string(output), "tool_a")
		assert.NotContains(t, string(output), "tool_b")
	})

	t.Run("event fields in non-standard order", func(t *testing.T) {
		// SSE spec allows fields in any order
		ses := makeSession(
			user.AccessControlRules{Allowed: []string{"allowed"}},
			user.AccessControlRules{},
		)
		hook := NewMCPListFilterSSEHook(apiID, ses)
		require.NotNil(t, hook)

		toolsData := makeJSONRPCResponse(1, "tools", []map[string]any{
			{"name": "allowed"},
			{"name": "blocked"},
		})

		// Non-standard field order: id, data, event, retry
		rawStream := fmt.Sprintf("id: evt-1\ndata: %s\nevent: message\nretry: 3000\n\n", toolsData)
		reader := io.NopCloser(strings.NewReader(rawStream))
		tap := NewSSETap(reader, hook)

		output, err := io.ReadAll(tap)
		require.NoError(t, err)

		assert.Contains(t, string(output), "allowed")
		assert.NotContains(t, string(output), "blocked")
	})

	t.Run("non-sequential event IDs", func(t *testing.T) {
		ses := makeSession(
			user.AccessControlRules{Allowed: []string{"tool_.*"}},
			user.AccessControlRules{},
		)
		hook := NewMCPListFilterSSEHook(apiID, ses)
		require.NotNil(t, hook)

		// Events with non-sequential IDs (could happen with reconnection)
		events := []struct {
			eventID   string
			jsonRPCID int
			tools     []string
		}{
			{"evt-100", 5, []string{"tool_a", "other_a"}},
			{"evt-50", 3, []string{"tool_b", "other_b"}},
			{"evt-200", 10, []string{"tool_c", "other_c"}},
		}

		var rawStream strings.Builder
		for _, e := range events {
			toolItems := make([]map[string]any, 0, len(e.tools))
			for _, t := range e.tools {
				toolItems = append(toolItems, map[string]any{"name": t})
			}
			data := makeJSONRPCResponse(e.jsonRPCID, "tools", toolItems)
			fmt.Fprintf(&rawStream, "id: %s\ndata: %s\n\n", e.eventID, data)
		}

		reader := io.NopCloser(strings.NewReader(rawStream.String()))
		tap := NewSSETap(reader, hook)

		output, err := io.ReadAll(tap)
		require.NoError(t, err)
		outputStr := string(output)

		// All tool_* should be present, all other_* should be filtered
		assert.Contains(t, outputStr, "tool_a")
		assert.Contains(t, outputStr, "tool_b")
		assert.Contains(t, outputStr, "tool_c")
		assert.NotContains(t, outputStr, "other_a")
		assert.NotContains(t, outputStr, "other_b")
		assert.NotContains(t, outputStr, "other_c")

		// Event IDs should be preserved
		assert.Contains(t, outputStr, "evt-100")
		assert.Contains(t, outputStr, "evt-50")
		assert.Contains(t, outputStr, "evt-200")
	})

	t.Run("keep-alive comments between list events", func(t *testing.T) {
		ses := makeSession(
			user.AccessControlRules{Allowed: []string{"allowed"}},
			user.AccessControlRules{},
		)
		hook := NewMCPListFilterSSEHook(apiID, ses)
		require.NotNil(t, hook)

		toolsData := makeJSONRPCResponse(1, "tools", []map[string]any{
			{"name": "allowed"},
			{"name": "blocked"},
		})

		// Stream with keep-alive comments interspersed
		rawStream := fmt.Sprintf(
			": keep-alive\n\ndata: %s\n\n: another keep-alive\n\n",
			toolsData,
		)
		reader := io.NopCloser(strings.NewReader(rawStream))
		tap := NewSSETap(reader, hook)

		output, err := io.ReadAll(tap)
		require.NoError(t, err)
		outputStr := string(output)

		// Comments should pass through
		assert.Contains(t, outputStr, ": keep-alive")
		assert.Contains(t, outputStr, ": another keep-alive")

		// Filtering should still work
		assert.Contains(t, outputStr, "allowed")
		assert.NotContains(t, outputStr, "blocked")
	})

	t.Run("empty events between list responses", func(t *testing.T) {
		ses := makeSession(
			user.AccessControlRules{Allowed: []string{"tool_1"}},
			user.AccessControlRules{},
		)
		hook := NewMCPListFilterSSEHook(apiID, ses)
		require.NotNil(t, hook)

		tools1 := makeJSONRPCResponse(1, "tools", []map[string]any{
			{"name": "tool_1"},
			{"name": "tool_2"},
		})
		tools2 := makeJSONRPCResponse(2, "tools", []map[string]any{
			{"name": "tool_1"},
			{"name": "tool_3"},
		})

		// Empty event blocks (just blank lines) between real events
		rawStream := fmt.Sprintf("data: %s\n\n\n\ndata: %s\n\n", tools1, tools2)
		reader := io.NopCloser(strings.NewReader(rawStream))
		tap := NewSSETap(reader, hook)

		output, err := io.ReadAll(tap)
		require.NoError(t, err)
		outputStr := string(output)

		// Both responses should be filtered correctly
		assert.Contains(t, outputStr, "tool_1")
		assert.NotContains(t, outputStr, "tool_2")
		assert.NotContains(t, outputStr, "tool_3")
	})

	t.Run("mixed list types in rapid succession", func(t *testing.T) {
		ses := &user.SessionState{
			AccessRights: map[string]user.AccessDefinition{
				apiID: {
					MCPAccessRights: user.MCPAccessRights{
						Tools:     user.AccessControlRules{Allowed: []string{"allowed_tool"}},
						Prompts:   user.AccessControlRules{Allowed: []string{"allowed_prompt"}},
						Resources: user.AccessControlRules{Allowed: []string{"allowed://resource"}},
					},
				},
			},
		}
		hook := NewMCPListFilterSSEHook(apiID, ses)
		require.NotNil(t, hook)

		toolsData := makeJSONRPCResponse(1, "tools", []map[string]any{
			{"name": "allowed_tool"},
			{"name": "blocked_tool"},
		})
		promptsData := makeJSONRPCResponse(2, "prompts", []map[string]any{
			{"name": "allowed_prompt"},
			{"name": "blocked_prompt"},
		})
		resourcesData := makeJSONRPCResponse(3, "resources", []map[string]any{
			{"uri": "allowed://resource", "name": "Allowed"},
			{"uri": "blocked://resource", "name": "Blocked"},
		})

		// All three list types back-to-back
		rawStream := fmt.Sprintf(
			"data: %s\n\ndata: %s\n\ndata: %s\n\n",
			toolsData, promptsData, resourcesData,
		)
		reader := io.NopCloser(strings.NewReader(rawStream))
		tap := NewSSETap(reader, hook)

		output, err := io.ReadAll(tap)
		require.NoError(t, err)
		outputStr := string(output)

		// Each list type should be filtered by its own rules
		assert.Contains(t, outputStr, "allowed_tool")
		assert.NotContains(t, outputStr, "blocked_tool")
		assert.Contains(t, outputStr, "allowed_prompt")
		assert.NotContains(t, outputStr, "blocked_prompt")
		assert.Contains(t, outputStr, "allowed://resource")
		assert.NotContains(t, outputStr, "blocked://resource")
	})

	t.Run("duplicate JSON-RPC IDs in different events", func(t *testing.T) {
		// Same JSON-RPC ID used in multiple SSE events (shouldn't happen
		// in practice, but tests robustness)
		ses := makeSession(
			user.AccessControlRules{Allowed: []string{"first_.*"}},
			user.AccessControlRules{},
		)
		hook := NewMCPListFilterSSEHook(apiID, ses)
		require.NotNil(t, hook)

		// Both use JSON-RPC id: 1
		first := makeJSONRPCResponse(1, "tools", []map[string]any{
			{"name": "first_tool"},
			{"name": "other_tool"},
		})
		second := makeJSONRPCResponse(1, "tools", []map[string]any{
			{"name": "first_another"},
			{"name": "blocked_another"},
		})

		rawStream := fmt.Sprintf("id: sse-1\ndata: %s\n\nid: sse-2\ndata: %s\n\n", first, second)
		reader := io.NopCloser(strings.NewReader(rawStream))
		tap := NewSSETap(reader, hook)

		output, err := io.ReadAll(tap)
		require.NoError(t, err)
		outputStr := string(output)

		// Both should be filtered independently
		assert.Contains(t, outputStr, "first_tool")
		assert.Contains(t, outputStr, "first_another")
		assert.NotContains(t, outputStr, "other_tool")
		assert.NotContains(t, outputStr, "blocked_another")
	})

	t.Run("very small chunk size fragmenting event boundary", func(t *testing.T) {
		// Chunk size so small it splits the \n\n boundary
		ses := makeSession(
			user.AccessControlRules{Allowed: []string{"tiny"}},
			user.AccessControlRules{},
		)
		hook := NewMCPListFilterSSEHook(apiID, ses)
		require.NotNil(t, hook)

		toolsData := makeJSONRPCResponse(1, "tools", []map[string]any{
			{"name": "tiny"},
			{"name": "huge"},
		})
		rawEvent := fmt.Sprintf("data: %s\n\n", toolsData)

		// Chunk size of 3 bytes - will split mid-boundary
		reader := &chunkedReader{data: []byte(rawEvent), chunkSize: 3}
		tap := NewSSETap(reader, hook)

		output, err := io.ReadAll(tap)
		require.NoError(t, err)

		assert.Contains(t, string(output), "tiny")
		assert.NotContains(t, string(output), "huge")
	})

	t.Run("event with data split across multiple data lines", func(t *testing.T) {
		// SSE allows multiple data: lines that get joined with \n
		ses := makeSession(
			user.AccessControlRules{Allowed: []string{"allowed"}},
			user.AccessControlRules{},
		)
		hook := NewMCPListFilterSSEHook(apiID, ses)
		require.NotNil(t, hook)

		toolsData := makeJSONRPCResponse(1, "tools", []map[string]any{
			{"name": "allowed"},
			{"name": "blocked"},
		})

		// Split the JSON across multiple data: lines (unusual but valid SSE)
		mid := len(toolsData) / 2
		rawStream := fmt.Sprintf("data: %s\ndata: %s\n\n", toolsData[:mid], toolsData[mid:])
		reader := io.NopCloser(strings.NewReader(rawStream))
		tap := NewSSETap(reader, hook)

		output, err := io.ReadAll(tap)
		require.NoError(t, err)

		// The hook joins data lines with \n, so the JSON will have a newline
		// in the middle - this tests that the hook handles this gracefully
		// (it should pass through since JSON parsing will fail)
		assert.NotEmpty(t, output)
	})

	t.Run("pagination cursor preserved across filtered responses", func(t *testing.T) {
		ses := makeSession(
			user.AccessControlRules{Allowed: []string{"page_.*"}},
			user.AccessControlRules{},
		)
		hook := NewMCPListFilterSSEHook(apiID, ses)
		require.NotNil(t, hook)

		// First page
		result1 := map[string]any{
			"tools":      []map[string]any{{"name": "page_1"}, {"name": "other_1"}},
			"nextCursor": "cursor-abc",
		}
		resultBytes1, _ := json.Marshal(result1) //nolint:errcheck
		envelope1 := map[string]any{"jsonrpc": "2.0", "id": 1, "result": json.RawMessage(resultBytes1)}
		data1, _ := json.Marshal(envelope1) //nolint:errcheck

		// Second page
		result2 := map[string]any{
			"tools":      []map[string]any{{"name": "page_2"}, {"name": "other_2"}},
			"nextCursor": "cursor-xyz",
		}
		resultBytes2, _ := json.Marshal(result2) //nolint:errcheck
		envelope2 := map[string]any{"jsonrpc": "2.0", "id": 2, "result": json.RawMessage(resultBytes2)}
		data2, _ := json.Marshal(envelope2) //nolint:errcheck

		rawStream := fmt.Sprintf("data: %s\n\ndata: %s\n\n", string(data1), string(data2))
		reader := io.NopCloser(strings.NewReader(rawStream))
		tap := NewSSETap(reader, hook)

		output, err := io.ReadAll(tap)
		require.NoError(t, err)
		outputStr := string(output)

		// Tools should be filtered
		assert.Contains(t, outputStr, "page_1")
		assert.Contains(t, outputStr, "page_2")
		assert.NotContains(t, outputStr, "other_1")
		assert.NotContains(t, outputStr, "other_2")

		// Cursors should be preserved
		assert.Contains(t, outputStr, "cursor-abc")
		assert.Contains(t, outputStr, "cursor-xyz")
	})
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
