package identifier_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/pkg/identifier"
)

func TestCustomId_Validate(t *testing.T) {
	testCases := []struct {
		name    string
		id      string
		invalid bool
	}{
		{name: "empty is generated, not user-defined", id: ""},
		{name: "letters and digits", id: "aZ09"},
		{name: "allowed punctuation", id: "a.b-c_d~e"},
		{name: "non-ascii letter", id: "żuk", invalid: true},
		{name: "path separator", id: "a/b", invalid: true},
		{name: "space", id: "a b", invalid: true},
		{name: "percent encoding", id: "a%2Fb", invalid: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policyErr := identifier.CustomPolicyId(tc.id).Validate()
			apiErr := identifier.CustomApiId(tc.id).Validate()

			if !tc.invalid {
				assert.NoError(t, policyErr)
				assert.NoError(t, apiErr)
				return
			}

			// Both types share the validation, but each reports its own error.
			assert.ErrorIs(t, policyErr, identifier.ErrInvalidCustomPolicyId)
			assert.ErrorIs(t, apiErr, identifier.ErrInvalidCustomApiId)
		})
	}
}

func TestCustomApiId_Validate_PunctuationOnly(t *testing.T) {
	// Dot-segments ("." and "..") are normalised away by HTTP clients and servers,
	// so an API stored under such an id could never be read, updated or deleted.
	for _, id := range []string{".", "..", "...", "-", "_", "~", ".-_~"} {
		t.Run(id, func(t *testing.T) {
			assert.ErrorIs(t, identifier.CustomApiId(id).Validate(), identifier.ErrInvalidCustomApiId)
		})
	}

	for _, id := range []string{"a.", "..1", "~x~", "v1.0"} {
		t.Run(id, func(t *testing.T) {
			assert.NoError(t, identifier.CustomApiId(id).Validate())
		})
	}

	// Policy IDs keep their existing rules.
	assert.NoError(t, identifier.CustomPolicyId(".").Validate())
}

func TestCustomId_String(t *testing.T) {
	assert.Equal(t, "pol-1", identifier.CustomPolicyId("pol-1").String())
	assert.Equal(t, "api-1", identifier.CustomApiId("api-1").String())
}
