package gateway

import (
	"context"
	"fmt"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3filter"
)

type ValidateRequest struct {
	BaseMiddleware
}

func (k *ValidateRequest) Name() string {
	return "ValidateRequest"
}

func (k *ValidateRequest) EnabledForSpec() bool {
	if !k.Spec.IsOAS {
		return false
	}

	middleware := k.Spec.OAS.GetTykExtension().Middleware
	if middleware == nil {
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
			k.Spec.HasValidateRequest = true
			return true
		}
	}

	return false
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *ValidateRequest) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	operation := ctxGetOperation(r)
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
		return fmt.Errorf("request validation error: %v", err), errResponseCode
	}

	// Handle Success
	return nil, http.StatusOK
}
