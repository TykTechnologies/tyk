package python

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Verifies: SYS-REQ-136, SW-REQ-123
// SYS-REQ-136:boundary:nominal
// SW-REQ-123:boundary:nominal
func TestDLPythonReqProof_VersionSelection(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		versions []string
		want     string
	}{
		{name: "major upgrade", versions: []string{"2.0", "3.5"}, want: "3.5"},
		{name: "minor upgrade", versions: []string{"3.5", "3.8"}, want: "3.8"},
		{name: "double digit minor", versions: []string{"3.9", "3.10"}, want: "3.10"},
		{name: "higher double digit minor", versions: []string{"3.9", "3.11"}, want: "3.11"},
		{name: "latest from ordered input", versions: []string{"3.11", "3.12"}, want: "3.12"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, selectLatestVersion(tc.versions))
		})
	}
}
