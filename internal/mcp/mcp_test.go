package mcp

import (
	"testing"

	"github.com/TykTechnologies/tyk/internal/agentprotocol"
	"github.com/TykTechnologies/tyk/internal/jsonrpc"
)

// Verifies: STK-REQ-019, SYS-REQ-107, SW-REQ-025
// STK-REQ-019:nominal:nominal
// SYS-REQ-107:nominal:nominal
// SW-REQ-025:nominal:nominal
func TestPrefixes(t *testing.T) {
	if ToolPrefix == "" || ResourcePrefix == "" || PromptPrefix == "" {
		t.Fatalf("prefixes must not be empty")
	}
}

// Verifies: STK-REQ-019, SYS-REQ-107, SW-REQ-025
// STK-REQ-019:boundary:boundary
// SYS-REQ-107:boundary:boundary
// SW-REQ-025:boundary:nominal
// SW-REQ-025:boundary:boundary
func TestIsPrimitiveVEMPath(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{ToolPrefix + "get-weather", true},
		{ResourcePrefix + "file:///repo/*", true},
		{PromptPrefix + "code-review", true},
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

// Verifies: STK-REQ-019, SYS-REQ-107, SW-REQ-025
// STK-REQ-019:nominal:nominal
// SYS-REQ-107:nominal:nominal
// SW-REQ-025:nominal:nominal
func TestRegisterVEMPrefixes(t *testing.T) {
	RegisterVEMPrefixes()

	if !agentprotocol.IsProtocolVEMPath(ToolPrefix + "get-weather") {
		t.Fatalf("tool VEM prefix was not registered")
	}
	if !agentprotocol.IsProtocolVEMPath(ResourcePrefix + "file:///repo/*") {
		t.Fatalf("resource VEM prefix was not registered")
	}
	if !agentprotocol.IsProtocolVEMPath(PromptPrefix + "code-review") {
		t.Fatalf("prompt VEM prefix was not registered")
	}
	if !agentprotocol.IsProtocolVEMPath(jsonrpc.MethodVEMPrefix + MethodToolsCall) {
		t.Fatalf("JSON-RPC method VEM prefix was not registered")
	}
}
