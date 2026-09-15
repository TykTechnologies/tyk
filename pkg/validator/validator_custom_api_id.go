package validator

import (
	govalidator "github.com/go-playground/validator/v10"

	"github.com/TykTechnologies/tyk/pkg/identifier"
)

func customApiIdValidator(fl govalidator.FieldLevel) bool {
	return identifier.CustomApiId(fl.Field().String()).Validate() == nil
}
