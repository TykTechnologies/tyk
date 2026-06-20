package identifier_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/pkg/identifier"
)

// Verifies: SW-REQ-022
// SW-REQ-022:nominal:nominal
// SW-REQ-022:boundary:nominal
// SW-REQ-022:boundary:boundary
// SW-REQ-022:error_handling:nominal
// SW-REQ-022:malformed_input:nominal
func TestCustomPolicyIdStringAndValidCharacters(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		id   identifier.CustomPolicyId
	}{
		{name: "empty unset identifier", id: ""},
		{name: "letters", id: "abcXYZ"},
		{name: "digits", id: "policy123"},
		{name: "allowed punctuation", id: "policy._-~"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, string(tc.id), tc.id.String())
			require.NoError(t, tc.id.Validate())
		})
	}
}

// Verifies: SW-REQ-022
// SW-REQ-022:error_handling:negative
// SW-REQ-022:malformed_input:negative
func TestCustomPolicyIdRejectsInvalidCharacters(t *testing.T) {
	t.Parallel()

	for _, id := range []identifier.CustomPolicyId{
		"policy/slash",
		"policy space",
		"policy:colon",
		"policy@host",
		"żuk",
	} {
		t.Run(id.String(), func(t *testing.T) {
			t.Parallel()

			err := id.Validate()
			require.Error(t, err)
			assert.True(t, errors.Is(err, identifier.ErrInvalidCustomPolicyId))
		})
	}
}
