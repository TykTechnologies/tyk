package uuid

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// Verifies: SYS-REQ-083, SW-REQ-001 [boundary]
// MCDC SW-REQ-001: uuid_operation_requested=T, uuid_operation_result_returned=F => FALSE
func TestCheckErrAndPanic(t *testing.T) {
	require.NotPanics(t, func() {
		checkErrAndPanic(nil, "uuid failed")
	})

	require.PanicsWithValue(t, "uuid failed boom", func() {
		checkErrAndPanic(errors.New("boom"), "uuid failed")
	})
}
