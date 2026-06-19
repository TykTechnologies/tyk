package rate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Verifies: SW-REQ-010
// SW-REQ-010:nominal:nominal
// SW-REQ-010:boundary:boundary
func TestPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		parts    []string
		expected string
	}{
		{
			name:     "joins non-empty fragments",
			parts:    []string{"a", "b", "c"},
			expected: "a-b-c",
		},
		{
			name:     "skips empty fragments",
			parts:    []string{"a", "b", "", "c"},
			expected: "a-b-c",
		},
		{
			name:     "trims dash separators",
			parts:    []string{"-rate-limit-", "--session--", "-allowance"},
			expected: "rate-limit-session-allowance",
		},
		{
			name:     "returns empty for empty or separator-only fragments",
			parts:    []string{"", "---", "--"},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, Prefix(tt.parts...))
		})
	}
}
