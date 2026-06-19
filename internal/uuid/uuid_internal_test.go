package uuid

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// Verifies: SYS-REQ-083, SW-REQ-001 [boundary]
func TestCheckErrAndPanic(t *testing.T) {
	require.NotPanics(t, func() {
		checkErrAndPanic(nil, "uuid failed")
	})

	require.PanicsWithValue(t, "uuid failed boom", func() {
		checkErrAndPanic(errors.New("boom"), "uuid failed")
	})
}
