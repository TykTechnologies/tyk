package build_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/build"
)

func TestCleanVersion(t *testing.T) {
	// Test cases
	tests := []struct {
		input    string
		expected string
	}{
		{"v1.2.3-beta", "v1.2.3"},
		{"version v2.10.0", "version v2.10.0"}, // No match, returns original
		{"v3.4.5", "v3.4.5"},
		{"v3.4.5rc9", "v3.4.5"},
		{"not-a-version", "not-a-version"}, // No match, returns original
		{"v0.1.0-rc.1", "v0.1.0"},
	}

	for _, tc := range tests {
		result := build.CleanVersion(tc.input)
		assert.Equal(t, tc.expected, result, "Expected %s but got %s", tc.expected, result)
	}
}
