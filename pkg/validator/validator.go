package validator

import (
	"errors"
	"reflect"

	govalidator "github.com/go-playground/validator/v10"

	"github.com/TykTechnologies/tyk/pkg/errpack"
	"github.com/TykTechnologies/tyk/pkg/identifier"
)

const customIdValidatorTag = "custom_id"

type Validator interface {
	Validate(v any) error
}

type Option func(*validatorCfg)

type ValidateFn func(val reflect.Value) error

type validatorCfg struct {
	disablePolicyIdValidation bool
}

type customValidator interface {
	Validate() error
}

func New(opts ...Option) Validator {
	validator := &validatorImpl{
		inner:    govalidator.New(),
		registry: make(map[reflect.Type]ValidateFn),
	}

	cfg := validatorCfg{}

	for _, apply := range opts {
		apply(&cfg)
	}

	if !cfg.disablePolicyIdValidation {
		validator.autoregister(identifier.Custom(""))
		validator.mustRegisterValidator(customIdValidatorTag, func(fl govalidator.FieldLevel) bool {
			return identifier.Custom(fl.Field().String()).Validate() == nil
		})
	} else {
		validator.mustRegisterValidator(customIdValidatorTag, func(_ govalidator.FieldLevel) bool {
			return true
		})
	}

	return validator
}

type validatorImpl struct {
	inner    *govalidator.Validate
	registry map[reflect.Type]ValidateFn
}

func (v *validatorImpl) Validate(obj any) error {
	val := reflect.ValueOf(obj)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if fn, ok := v.registry[val.Type()]; ok {
		if err := fn(val); err != nil {
			return err
		}
	}

	if val.Kind() == reflect.Struct {
		err := v.inner.Struct(obj)

		if err == nil {
			return nil
		}

		var ve govalidator.ValidationErrors
		if errors.As(err, &ve) {
			return v.formatError(ve)
		}

		return err
	}

	return nil
}

func (v *validatorImpl) formatError(ve govalidator.ValidationErrors) error {
	fe := ve[0]
	switch fe.Tag() {
	case customIdValidatorTag:
		return errpack.Domainf("field %s: has invalid custom identifier format", fe.Field())
	default:
		return errpack.Domainf("field %s: failed validation on %s", fe.Field(), fe.Tag())
	}
}

func (v *validatorImpl) mustRegisterValidator(tag string, fn govalidator.Func, callValidationEvenIfNull ...bool) {
	if err := v.inner.RegisterValidation(tag, fn, callValidationEvenIfNull...); err != nil {
		panic(err)
	}
}

func (v *validatorImpl) autoregister(val customValidator) {
	v.registry[reflect.TypeOf(val)] = func(val reflect.Value) error {
		if v, ok := val.Interface().(customValidator); !ok {
			return errpack.New("invalid business logic", errpack.WithType(errpack.BrokenInvariant))
		} else {
			return v.Validate()
		}
	}
}

func WithDisabledPolicyIdValidation(disabled bool) Option {
	return func(cfg *validatorCfg) {
		cfg.disablePolicyIdValidation = disabled
	}
}
