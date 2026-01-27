package mcp

import (
	"testing"
)

func TestPrefixes(t *testing.T) {
	if ToolPrefix == "" || ResourcePrefix == "" || PromptPrefix == "" {
		t.Fatalf("prefixes must not be empty")
	}
}
