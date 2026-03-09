package mcp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/user"
)

func TestExtractStringField(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		field string
		want  string
	}{
		{
			name:  "existing string field",
			raw:   `{"name":"get_weather","description":"Get weather"}`,
			field: "name",
			want:  "get_weather",
		},
		{
			name:  "missing field",
			raw:   `{"description":"Get weather"}`,
			field: "name",
			want:  "",
		},
		{
			name:  "non-string field",
			raw:   `{"name":42}`,
			field: "name",
			want:  "",
		},
		{
			name:  "invalid JSON",
			raw:   `{not json}`,
			field: "name",
			want:  "",
		},
		{
			name:  "empty object",
			raw:   `{}`,
			field: "name",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractStringField(json.RawMessage(tt.raw), tt.field)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCheckAccessControlRules(t *testing.T) {
	tests := []struct {
		name    string
		rules   user.AccessControlRules
		input   string
		wantErr bool
	}{
		// Empty rules — everything passes
		{"empty rules, any input passes", user.AccessControlRules{}, "anything", false},
		{"empty rules, empty input passes", user.AccessControlRules{}, "", false},

		// Blocked only
		{"blocked exact match", user.AccessControlRules{Blocked: []string{"tools/list"}}, "tools/list", true},
		{"blocked no match", user.AccessControlRules{Blocked: []string{"tools/list"}}, "tools/call", false},
		{"blocked regex match", user.AccessControlRules{Blocked: []string{"delete_.*"}}, "delete_user", true},
		{"blocked regex no match", user.AccessControlRules{Blocked: []string{"delete_.*"}}, "create_user", false},
		{"blocked suffix regex", user.AccessControlRules{Blocked: []string{".*_admin"}}, "user_admin", true},
		{"blocked suffix regex no match", user.AccessControlRules{Blocked: []string{".*_admin"}}, "user_create", false},
		{"blocked multiple patterns, first matches", user.AccessControlRules{Blocked: []string{"delete_.*", "reset_.*"}}, "delete_all", true},
		{"blocked multiple patterns, second matches", user.AccessControlRules{Blocked: []string{"delete_.*", "reset_.*"}}, "reset_config", true},
		{"blocked multiple patterns, none match", user.AccessControlRules{Blocked: []string{"delete_.*", "reset_.*"}}, "get_data", false},

		// Allowed only
		{"allowed exact match", user.AccessControlRules{Allowed: []string{"tools/call"}}, "tools/call", false},
		{"allowed not in list", user.AccessControlRules{Allowed: []string{"tools/call"}}, "tools/list", true},
		{"allowed regex match", user.AccessControlRules{Allowed: []string{"get_.*"}}, "get_weather", false},
		{"allowed regex no match", user.AccessControlRules{Allowed: []string{"get_.*"}}, "set_config", true},
		{"allowed multiple patterns, first matches", user.AccessControlRules{Allowed: []string{"get_.*", "list_.*"}}, "get_weather", false},
		{"allowed multiple patterns, second matches", user.AccessControlRules{Allowed: []string{"get_.*", "list_.*"}}, "list_users", false},
		{"allowed multiple patterns, none match", user.AccessControlRules{Allowed: []string{"get_.*", "list_.*"}}, "delete_all", true},

		// Both — blocked takes precedence
		{"deny precedence over allow (exact)",
			user.AccessControlRules{Blocked: []string{"reset_system"}, Allowed: []string{"reset_system"}},
			"reset_system", true},
		{"deny precedence over allow (regex)",
			user.AccessControlRules{Blocked: []string{".*_system"}, Allowed: []string{"reset_.*"}},
			"reset_system", true},
		{"allowed passes when not in blocked",
			user.AccessControlRules{Blocked: []string{"delete_.*"}, Allowed: []string{"get_.*", "delete_.*"}},
			"get_weather", false},

		{"alternation: allowed prefix match", user.AccessControlRules{Allowed: []string{"get_.*|set_.*"}}, "get_weather", false},
		{"alternation: allowed second branch", user.AccessControlRules{Allowed: []string{"get_.*|set_.*"}}, "set_config", false},
		{"alternation: denied non-matching", user.AccessControlRules{Allowed: []string{"get_.*|set_.*"}}, "delete_all", true},
		{"alternation: allowed spurious prefix leak", user.AccessControlRules{Allowed: []string{"get_.*|set_.*"}}, "bad_prefix_set_foo", true},
		{"alternation: blocked spurious trailing leak", user.AccessControlRules{Blocked: []string{"admin|debug"}}, "prefix_debug", false},

		// Edge cases
		{"pattern with URI chars", user.AccessControlRules{Allowed: []string{"file:///public/.*"}}, "file:///public/readme.md", false},
		{"pattern with URI chars, no match", user.AccessControlRules{Allowed: []string{"file:///public/.*"}}, "file:///secret/keys.txt", true},
		{"invalid regex falls back to exact, exact match", user.AccessControlRules{Blocked: []string{"[invalid"}}, "[invalid", true},
		{"invalid regex falls back to exact, no match", user.AccessControlRules{Blocked: []string{"[invalid"}}, "something", false},
		{"method name with slash", user.AccessControlRules{Blocked: []string{"tools/list"}}, "tools/list", true},
		{"method regex with slash", user.AccessControlRules{Allowed: []string{"resources/.*"}}, "resources/read", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			denied := CheckAccessControlRules(tt.rules, tt.input)
			if tt.wantErr {
				assert.True(t, denied, "expected denied for input %q", tt.input)
			} else {
				assert.False(t, denied, "expected allowed for input %q", tt.input)
			}
		})
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		// Exact matches
		{"get_weather", "get_weather", true},
		{"get_weather", "get_weather_v2", false}, // anchored: no partial match
		{"tools/call", "tools/call", true},
		{"tools/call", "tools/list", false},

		// Prefix wildcards
		{"get_.*", "get_weather", true},
		{"get_.*", "set_config", false},
		{"resources/.*", "resources/read", true},
		{"resources/.*", "prompts/get", false},

		// Suffix wildcards
		{".*_admin", "user_admin", true},
		{".*_admin", "user_create", false},
		{".*_delete", "record_delete", true},

		// Regex alternation
		{"get_.*|set_.*", "get_weather", true},
		{"get_.*|set_.*", "set_config", true},
		{"get_.*|set_.*", "delete_all", false},
		{"get_.*|set_.*", "bad_prefix_set_foo", false},
		{"get_.*|set_.*", "get_weather_extra", true},
		{"a|b", "xb", false},
		{"a|b", "ax", false},
		{"a|b", "a", true},
		{"a|b", "b", true},

		// URI patterns with slashes
		{"file:///.*", "file:///repo/README", true},
		{"file:///public/.*", "file:///public/readme.md", true},
		{"file:///public/.*", "file:///secret/keys.txt", false},

		// Invalid regex — falls back to exact comparison
		{"[invalid", "[invalid", true},
		{"[invalid", "something", false},

		// Empty cases
		{".*", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_vs_"+tt.name, func(t *testing.T) {
			got := matchPattern(tt.pattern, tt.name)
			assert.Equal(t, tt.want, got, "matchPattern(%q, %q)", tt.pattern, tt.name)
		})
	}
}

func TestFilterItems(t *testing.T) {
	t.Run("empty items array returns empty", func(t *testing.T) {
		rules := user.AccessControlRules{Allowed: []string{"anything"}}
		result := FilterItems([]json.RawMessage{}, "name", rules)
		assert.Empty(t, result)
	})

	t.Run("items missing name field are included (fail-open)", func(t *testing.T) {
		items := []json.RawMessage{
			json.RawMessage(`{"name":"keep_me","description":"has name"}`),
			json.RawMessage(`{"description":"no name field at all"}`),
			json.RawMessage(`{"name":"block_me","description":"will be blocked"}`),
		}
		rules := user.AccessControlRules{Blocked: []string{"block_me"}}
		result := FilterItems(items, "name", rules)
		assert.Len(t, result, 2, "item without name field should be included (fail-open)")

		// Verify the kept items.
		names := make([]string, 0, len(result))
		for _, item := range result {
			n := ExtractStringField(item, "name")
			names = append(names, n)
		}
		assert.Contains(t, names, "keep_me")
		assert.Contains(t, names, "", "nameless item should pass through with empty name")
	})

	t.Run("items with non-string name field are included (fail-open)", func(t *testing.T) {
		items := []json.RawMessage{
			json.RawMessage(`{"name":42,"description":"numeric name"}`),
			json.RawMessage(`{"name":true,"description":"boolean name"}`),
			json.RawMessage(`{"name":"normal","description":"string name"}`),
		}
		rules := user.AccessControlRules{Allowed: []string{"normal"}}
		result := FilterItems(items, "name", rules)
		// Items with non-string names can't be extracted — fail-open includes them.
		assert.Len(t, result, 3)
	})

	t.Run("invalid regex in rules falls back to exact match", func(t *testing.T) {
		items := []json.RawMessage{
			json.RawMessage(`{"name":"[unclosed","description":"literal bracket name"}`),
			json.RawMessage(`{"name":"normal_tool","description":"normal"}`),
		}
		// "[unclosed" is an invalid regex — should fall back to exact string comparison.
		rules := user.AccessControlRules{Blocked: []string{"[unclosed"}}
		result := FilterItems(items, "name", rules)
		assert.Len(t, result, 1, "invalid regex should still match by exact string comparison")
		assert.Equal(t, "normal_tool", ExtractStringField(result[0], "name"))
	})
}

func TestFilterJSONRPCBody(t *testing.T) {
	t.Run("batch JSON-RPC array passes through (returns false)", func(t *testing.T) {
		// JSON-RPC batch = top-level array. Not supported for filtering.
		batch := `[{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"}]}},{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"b"}]}}]`
		cfg := ListFilterConfigs["tools"]
		rules := user.AccessControlRules{Allowed: []string{"a"}}
		result, ok := FilterJSONRPCBody([]byte(batch), cfg, rules)
		assert.False(t, ok, "batch responses should not be parsed")
		assert.Nil(t, result)
	})

	t.Run("error response with no result passes through", func(t *testing.T) {
		errResp := `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"invalid request"}}`
		cfg := ListFilterConfigs["tools"]
		rules := user.AccessControlRules{Blocked: []string{".*"}}
		result, ok := FilterJSONRPCBody([]byte(errResp), cfg, rules)
		assert.False(t, ok)
		assert.Nil(t, result)
	})

	t.Run("empty result object passes through", func(t *testing.T) {
		emptyResult := `{"jsonrpc":"2.0","id":1,"result":{}}`
		cfg := ListFilterConfigs["tools"]
		rules := user.AccessControlRules{Allowed: []string{"anything"}}
		result, ok := FilterJSONRPCBody([]byte(emptyResult), cfg, rules)
		assert.False(t, ok, "empty result with no array key should pass through")
		assert.Nil(t, result)
	})

	t.Run("unicode tool names are matched correctly", func(t *testing.T) {
		body := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"résumé_tool"},{"name":"日本語ツール"},{"name":"normal_tool"}]}}`
		cfg := ListFilterConfigs["tools"]
		rules := user.AccessControlRules{Allowed: []string{"résumé_tool", "normal_tool"}}
		result, ok := FilterJSONRPCBody([]byte(body), cfg, rules)
		require.True(t, ok)

		var envelope JSONRPCResponse
		require.NoError(t, json.Unmarshal(result, &envelope))
		var res map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(envelope.Result, &res))
		var tools []map[string]any
		require.NoError(t, json.Unmarshal(res["tools"], &tools))
		assert.Len(t, tools, 2)
		names := []string{tools[0]["name"].(string), tools[1]["name"].(string)}
		assert.Contains(t, names, "résumé_tool")
		assert.Contains(t, names, "normal_tool")
	})
}

func TestInferListConfigFromResult(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{"tools", "tools", "tools"},
		{"prompts", "prompts", "prompts"},
		{"resources", "resources", "resources"},
		{"resourceTemplates", "resourceTemplates", "resourceTemplates"},
		{"content (not a list)", "content", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := map[string]json.RawMessage{
				tt.key: json.RawMessage(`[]`),
			}
			cfg := InferListConfigFromResult(result)
			if tt.expected == "" {
				assert.Nil(t, cfg)
			} else {
				require.NotNil(t, cfg)
				assert.Equal(t, tt.expected, cfg.ArrayKey)
			}
		})
	}

	t.Run("ambiguous keys returns first in lookup order", func(t *testing.T) {
		// Result with both "tools" and "prompts" — should return tools (first in order).
		result := map[string]json.RawMessage{
			"tools":   json.RawMessage(`[]`),
			"prompts": json.RawMessage(`[]`),
		}
		cfg := InferListConfigFromResult(result)
		require.NotNil(t, cfg)
		assert.Equal(t, "tools", cfg.ArrayKey)
	})

	t.Run("empty result returns nil", func(t *testing.T) {
		result := map[string]json.RawMessage{}
		cfg := InferListConfigFromResult(result)
		assert.Nil(t, cfg)
	})
}
