package model_test

import (
	"testing"

	persistentmodel "github.com/TykTechnologies/storage/persistent/model"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/user"
	"github.com/stretchr/testify/assert"
)

func Test_EnsurePolicyId(t *testing.T) {
	objectId := persistentmodel.NewObjectID()

	for _, tc := range []struct {
		name           string
		input          *user.Policy
		expectedResult bool
		expectedId     string
	}{
		{
			name:           "skips if id is provided and MID is invalid",
			input:          &user.Policy{ID: "my-custom-id"},
			expectedResult: true,
			expectedId:     "my-custom-id",
		},
		{
			name:           "skips if id is provided and MID is valid",
			input:          &user.Policy{MID: objectId, ID: "my-custom-id"},
			expectedResult: true,
			expectedId:     "my-custom-id",
		},
		{
			name:           "returns false if is is not provided and MID is invalid",
			input:          &user.Policy{ID: "", MID: "invalid"},
			expectedResult: false,
			expectedId:     "",
		},
		{
			name:           "returns true and sets id if ID is not defined and MID is valid",
			input:          &user.Policy{ID: "", MID: objectId},
			expectedResult: true,
			expectedId:     objectId.Hex(),
		},
		{
			name:           "returns false if provided policy is nil",
			input:          nil,
			expectedResult: false,
			expectedId:     "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := model.EnsurePolicyId(tc.input)
			assert.Equal(t, tc.expectedResult, res)

			if tc.input != nil {
				assert.Equal(t, tc.expectedId, tc.input.ID)
			}
		})
	}
}
