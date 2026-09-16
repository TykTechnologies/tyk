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
		{name: "only punctuation", id: ".-_~"},
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

func TestCustomId_String(t *testing.T) {
	assert.Equal(t, "pol-1", identifier.CustomPolicyId("pol-1").String())
	assert.Equal(t, "api-1", identifier.CustomApiId("api-1").String())
}
