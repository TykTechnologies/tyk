package gateway

import (
	"net/http"
	// TODO: For OAS 3.1 support - re-enable these imports when implementing libopenapi-validator
	// "context"
	// "fmt" 
	// "time"
	// "github.com/pb33f/libopenapi"
	// validator "github.com/pb33f/libopenapi-validator"
)

func init() {
	// TODO: For OAS 3.1 support - implement schema format callbacks with libopenapi
	// The following configurations need to be migrated to libopenapi equivalents:
	// - SchemaErrorDetailsDisabled 
	// - Date-time format validation
	// - Date format validation
	
	// Temporarily disabled during migration to libopenapi
	/*
	openapi3.SchemaErrorDetailsDisabled = true
	openapi3.DefineStringFormatCallback("date-time", func(value string) error {
		_, err := time.Parse(time.RFC3339, value)
		return err
	})

	openapi3.DefineStringFormatCallback("date", func(value string) error {
		_, err := time.Parse(time.DateOnly, value)
		return err
	})
	*/
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

	// TODO: For OAS 3.1 support - re-enable error response code when implementing validation
	/*
	errResponseCode := http.StatusUnprocessableEntity
	if validateRequest.ErrorResponseCode != 0 {
		errResponseCode = validateRequest.ErrorResponseCode
	}
	*/

	// TODO: For OAS 3.1 support - migrate to libopenapi-validator
	// The current implementation needs to be updated to work with libopenapi
	// This requires changes to how the OAS document is stored and accessed
	
	// Temporarily disabled during migration to libopenapi - will always pass validation
	_ = operation // Suppress unused variable warning
	
	// Placeholder implementation - need to implement proper libopenapi-validator integration
	// Steps needed:
	// 1. Get libopenapi.Document from k.Spec.OAS (requires OAS struct migration)
	// 2. Create validator from document
	// 3. Use validator.ValidateHttpRequest(r) instead of openapi3filter.ValidateRequest
	
	/*
	// Future implementation should look like:
	document := k.Spec.OAS.Document // Need to update OAS struct to have Document field
	if document == nil {
		return fmt.Errorf("no OAS document available for validation"), http.StatusUnprocessableEntity
	}
	
	httpValidator, errs := validator.NewValidator(document)
	if len(errs) > 0 {
		return fmt.Errorf("failed to create validator: %v", errs), http.StatusUnprocessableEntity
	}
	
	valid, validationErrors := httpValidator.ValidateHttpRequest(r)
	if !valid {
		var errMsgs []string
		for _, validationError := range validationErrors {
			errMsgs = append(errMsgs, validationError.Message)
		}
		return fmt.Errorf("request validation error: %s", strings.Join(errMsgs, "; ")), http.StatusUnprocessableEntity
	}
	*/

	// Handle Success
	return nil, http.StatusOK
}
