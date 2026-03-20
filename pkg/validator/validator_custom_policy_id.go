package validator

import (
	govalidator "github.com/go-playground/validator/v10"

	"github.com/TykTechnologies/tyk/pkg/identifier"
)

func customPolicyIdValidator(fl govalidator.FieldLevel) bool {
	return identifier.CustomPolicyId(fl.Field().String()).Validate() == nil
}
