package errors

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// Verifies: STK-REQ-019, SYS-REQ-107, SW-REQ-040
// STK-REQ-019:encoding_safety:nominal
// SYS-REQ-107:encoding_safety:nominal
// SW-REQ-040:encoding_safety:nominal
func TestErrorFormatter(t *testing.T) {
	tests := []struct {
		name     string
		errs     []error
		expected string
	}{
		{
			name:     "No errors",
			errs:     []error{},
			expected: "",
		},
		{
			name:     "Single error",
			errs:     []error{errors.New("error 1")},
			expected: "error 1",
		},
		{
			name:     "Multiple errors",
			errs:     []error{errors.New("error 1"), errors.New("error 2")},
			expected: "error 1\nerror 2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := Formatter(tc.errs)
			if result != tc.expected {
				t.Errorf("Formatter() = %v, want %v", result, tc.expected)
			}
		})
	}
}

// Verifies: STK-REQ-019, SYS-REQ-107, SW-REQ-040
// STK-REQ-019:nominal:nominal
// STK-REQ-019:error_handling:negative
// SYS-REQ-107:nominal:nominal
// SYS-REQ-107:error_handling:negative
// SW-REQ-040:nominal:nominal
// SW-REQ-040:error_handling:negative
func TestErrorFacadeRequirement(t *testing.T) {
	base := New("base")
	wrapped := fmt.Errorf("wrapped: %w", base)

	require.True(t, Is(wrapped, base))
	require.Equal(t, base, Unwrap(wrapped))

	joined := Join(wrapped, ErrUnsupported)
	require.True(t, Is(joined, base))
	require.True(t, Is(joined, ErrUnsupported))

	var target interface{ Error() string }
	require.True(t, As(wrapped, &target))
	require.Equal(t, "wrapped: base", target.Error())
}
