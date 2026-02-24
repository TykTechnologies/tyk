package validator_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/pkg/errpack"
	"github.com/TykTechnologies/tyk/pkg/identifier"
	tykvalidator "github.com/TykTechnologies/tyk/pkg/validator"
)

func Test_Validate(t *testing.T) {
	type parentStruct struct {
		Id string `validate:"custom_id"`
	}

	t.Run("WithDisabledPolicyIdValidation=true", func(t *testing.T) {
		validator := tykvalidator.New(tykvalidator.WithDisabledPolicyIdValidation(true))

		t.Run("ignores invalid custom_id", func(t *testing.T) {
			id := identifier.Custom("żuk")
			err := validator.Validate(id)
			assert.NoError(t, err)
		})

		t.Run("ignores build-in custom_id tag", func(t *testing.T) {
			err := validator.Validate(&parentStruct{
				Id: "żuk",
			})
			assert.NoError(t, err)
		})
	})

	t.Run("WithDisabledPolicyIdValidation=false", func(t *testing.T) {
		validator := tykvalidator.New(tykvalidator.WithDisabledPolicyIdValidation(false))

		t.Run("validates", func(t *testing.T) {
			id := identifier.Custom("żuk")
			err := validator.Validate(id)
			assert.ErrorIs(t, err, identifier.ErrInvalidCustomId)
		})

		t.Run("rejects validation of build-in struct", func(t *testing.T) {
			err := validator.Validate(&parentStruct{
				Id: "żuk",
			})
			assert.Error(t, err)
			var errp errpack.Error
			assert.ErrorAs(t, err, &errp)
			assert.True(t, errp.TypeOf(errpack.TypeDomain))
		})
	})
}
