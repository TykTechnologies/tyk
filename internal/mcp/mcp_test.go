package mcp

import (
	"testing"
)

func TestPrefixes(t *testing.T) {
	if ToolPrefix == "" || ResourcePrefix == "" || PromptPrefix == "" {
		t.Fatalf("prefixes must not be empty")
	}
}

func TestIsPrimitiveVEMPath(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/mcp-tool:get-weather", true},
		{"/mcp-resource:file:///repo/*", true},
		{"/mcp-prompt:code-review", true},
		{"/api/v1/users", false},
		{"/mcp-tools", false}, // missing colon
		{"", false},
	}

	for _, tt := range tests {
		if got := IsPrimitiveVEMPath(tt.path); got != tt.expected {
			t.Errorf("IsPrimitiveVEMPath(%q) = %v, want %v", tt.path, got, tt.expected)
		}
	}
}
