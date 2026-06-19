package agentprotocol

import "testing"

// Verifies: SYS-REQ-107, SW-REQ-027
// SYS-REQ-107:nominal:nominal
// SW-REQ-027:nominal:nominal
func TestRegisterVEMPrefix(t *testing.T) {
	const prefix = "/reqproof-agent-vem:"

	RegisterVEMPrefix(prefix)

	if !IsProtocolVEMPath(prefix + "operation") {
		t.Fatalf("registered VEM prefix was not recognized")
	}
}

// Verifies: SYS-REQ-107, SW-REQ-027
// SYS-REQ-107:boundary:boundary
// SW-REQ-027:boundary:boundary
func TestIsProtocolVEMPath_UnregisteredPath(t *testing.T) {
	if IsProtocolVEMPath("/unregistered-agent-vem:operation") {
		t.Fatalf("unregistered VEM prefix was recognized")
	}
}
