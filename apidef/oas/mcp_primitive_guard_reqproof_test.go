package oas

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Verifies: SYS-REQ-107, SW-REQ-064
// SW-REQ-064:nominal:nominal
// SW-REQ-064:access_denied:nominal
// SW-REQ-064:access_denied:negative
// SW-REQ-064:boundary:nominal
func TestMCPPrimitiveGuardBuildModeBehavior(t *testing.T) {
	operation := &Operation{Allow: &Allowance{Enabled: true}}
	primitive := &MCPPrimitive{}

	require.NotPanics(t, func() {
		ensureNotBypassingOverride(primitive)
	})
	require.NotPanics(t, func() {
		ensureNotBypassingOverride(nil)
	})

	if mcpPrimitiveGuardPanicsForOperation {
		require.Panics(t, func() {
			ensureNotBypassingOverride(operation)
		})
		return
	}

	require.NotPanics(t, func() {
		ensureNotBypassingOverride(operation)
	})
}
