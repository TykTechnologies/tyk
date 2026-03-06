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
}
