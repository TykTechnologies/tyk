package gateway

import (
	"context"
	"errors"
	"fmt"
	"github.com/TykTechnologies/tyk/ctx"
	"net/http"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/getkin/kin-openapi/openapi3filter"
)

func init() {
	openapi3.SchemaErrorDetailsDisabled = true
	openapi3.DefineStringFormatCallback("date-time", func(value string) error {
		_, err := time.Parse(time.RFC3339, value)
		return err
	})

	openapi3.DefineStringFormatCallback("date", func(value string) error {
		_, err := time.Parse(time.DateOnly, value)
		return err
	})
}

type ValidateRequest struct {
	*BaseMiddleware
}

func (k *ValidateRequest) Name() string {
	return "ValidateRequest"
}

func (k *ValidateRequest) EnabledForSpec() bool {
	if !k.Spec.IsOAS {
		return false
	}

	extension := k.Spec.OAS.GetTykExtension()
	if extension == nil {
		return false
	}

	middleware := extension.Middleware
	if extension.Middleware == nil {
		return false
	}

	if len(middleware.Operations) == 0 {
		return false
	}

	for _, operation := range middleware.Operations {
		if operation.ValidateRequest == nil {
			continue
		}

		if operation.ValidateRequest.Enabled {
			return true
		}
	}

	return false
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *ValidateRequest) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	operation := k.Spec.findOperation(r)

	if operation == nil {
		return nil, http.StatusOK
	}

	validateRequest := operation.ValidateRequest
	if validateRequest == nil || !validateRequest.Enabled {
		return nil, http.StatusOK
	}

	errResponseCode := http.StatusUnprocessableEntity
	if validateRequest.ErrorResponseCode != 0 {
		errResponseCode = validateRequest.ErrorResponseCode
	}

	// Validate request
	requestValidationInput := &openapi3filter.RequestValidationInput{
		Request:    r,
		PathParams: operation.pathParams,
		Route:      operation.route,
		Options: &openapi3filter.Options{
			AuthenticationFunc: func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
				return nil
			},
		},
	}

	err := openapi3filter.ValidateRequest(r.Context(), requestValidationInput)
	if err != nil {
		details := validationErrorDetails(ErrNotValidSchema, err)
		ctx.SetErrorInfo(r, ErrNotValidSchema, err, details)

		return fmt.Errorf("request validation error: %w", err), errResponseCode
	}

	// Handle Success
	return nil, http.StatusOK
}

// FieldError represents a validation error for a specific field,
// containing the field's JSON pointer path and the reason for the error.
type FieldError struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// Converts []FieldError to flat map[string]interface{}: field -> reason
func validationErrorDetails(errorId string, err error) ctx.ErrorContextData {
	fieldErrors := structureError(err)
	errorsAsMap := make(map[string]interface{}, len(fieldErrors))
	for _, fe := range fieldErrors {
		if fe.Field != "" {
			errorsAsMap[fe.Field] = fe.Reason
		}
	}
	return ctx.BuildTemplateContext(errorsAsMap, errorId, err)
}

// structureError parses an error from openapi3filter.ValidateRequest,
// extracting validation issues as a slice of FieldError with JSON pointer paths and reasons.
// Returns one generic error if no detailed validation errors found.
func structureError(err error) []FieldError {
	var fieldErrors []FieldError

	var reqErr *openapi3filter.RequestError
	if errors.As(err, &reqErr) {
		switch e := reqErr.Err.(type) {
		case openapi3.MultiError:
			for _, subErr := range e {
				if schemaErr, ok := subErr.(*openapi3.SchemaError); ok {
					fieldErrors = append(fieldErrors, FieldError{
						Field:  jsonPointerToString(schemaErr.JSONPointer()),
						Reason: schemaErr.Reason,
					})
				}
			}
		case *openapi3.SchemaError:
			fieldErrors = append(fieldErrors, FieldError{
				Field:  jsonPointerToString(e.JSONPointer()),
				Reason: e.Reason,
			})
		default:
			fieldErrors = append(fieldErrors, FieldError{
				Field:  "",
				Reason: reqErr.Err.Error(),
			})
		}
	} else {
		fieldErrors = append(fieldErrors, FieldError{
			Field:  "",
			Reason: err.Error(),
		})
	}

	return fieldErrors
}

// jsonPointerToString converts a JSON pointer represented as a slice of strings
// into a slash-separated string path (e.g., ["user", "email"] -> "user/email").
// Returns an empty string if the input slice is empty.
func jsonPointerToString(pointer []string) string {
	if len(pointer) == 0 {
		return ""
	}
	return strings.Join(pointer, "/")
}
