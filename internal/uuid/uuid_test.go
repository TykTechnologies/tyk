package uuid_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/uuid"
)

// Verifies: SYS-REQ-083, SW-REQ-001
// SYS-REQ-083:nominal:nominal
// SW-REQ-001:nominal:nominal
// MCDC SYS-REQ-083: uuid_operation_requested=T, uuid_operation_result_returned=T => TRUE
// MCDC SW-REQ-001: uuid_operation_requested=T, uuid_operation_result_returned=T => TRUE
func TestUUID(t *testing.T) {
	id := uuid.New()

	require.NotEmpty(t, id)
	require.True(t, uuid.Valid(id))
	require.Contains(t, id, "-")
}

// Verifies: SYS-REQ-083, SW-REQ-001
func TestUUIDHex(t *testing.T) {
	id := uuid.NewHex()

	require.NotEmpty(t, id)
	require.True(t, uuid.Valid(id))
	require.NotContains(t, id, "-")
}

// Verifies: SYS-REQ-083, SW-REQ-001 [malformed]
// SYS-REQ-083:malformed_input:nominal
// SYS-REQ-083:malformed_input:negative
// SYS-REQ-083:boundary:nominal
// SW-REQ-001:malformed_input:nominal
// SW-REQ-001:malformed_input:negative
// SW-REQ-001:boundary:nominal
// MCDC SYS-REQ-083: uuid_operation_requested=F, uuid_operation_result_returned=F => TRUE
// MCDC SYS-REQ-083: uuid_operation_requested=T, uuid_operation_result_returned=F => FALSE
// MCDC SW-REQ-001: uuid_operation_requested=F, uuid_operation_result_returned=F => TRUE
// MCDC SW-REQ-001: uuid_operation_requested=T, uuid_operation_result_returned=F => FALSE
func TestUUIDValid(t *testing.T) {
	id := uuid.New()

	require.True(t, uuid.Valid(id))
	require.True(t, uuid.Valid(uuid.NewHex()))
	require.False(t, uuid.Valid(""))
	require.False(t, uuid.Valid("not-a-uuid"))
}
