package gateway

import (
	"context"
	"fmt"
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

var specialHeaders = map[string]bool{
	"Set-Cookie":         true,
	"Www-Authenticate":   true,
	"Proxy-Authenticate": true,
	"Warning":            true,
	"Content-Length":     true,
	"Content-Type":       true,
	"Location":           true,
	"Etag":               true,
}

// containsComma checks if any value in the slice contains a comma.
// This is used to detect cases where combining values would break parsing.
func containsComma(values []string) bool {
	for _, v := range values {
		if strings.Contains(v, ",") {
			return true
		}
	}
	return false
}

// normalizeHeaders creates a normalized copy of headers for OpenAPI validation.
// Multiple headers with the same name are combined into a comma-separated value
// according to HTTP standards, with exceptions for special headers.
func normalizeHeaders(headers http.Header) http.Header {
	normalized := make(http.Header)

	for key, values := range headers {
		canonicalKey := http.CanonicalHeaderKey(key)

		if len(values) == 0 {
			continue
		}

		if len(values) == 1 {
			normalized.Set(canonicalKey, values[0])
			continue
		}

		if specialHeaders[canonicalKey] {
			normalized.Set(canonicalKey, values[0])
			continue
		}

		if containsComma(values) {
			normalized.Set(canonicalKey, values[0])
			continue
		}

		normalized.Set(canonicalKey, strings.Join(values, ","))
	}

	return normalized
}

// cloneRequestWithNormalizedHeaders creates a shallow copy of the request
// with normalized headers for OpenAPI validation.
// This preserves the original request while allowing header normalization.
func cloneRequestWithNormalizedHeaders(r *http.Request) *http.Request {
	clone := r.Clone(r.Context())

	clone.Header = normalizeHeaders(r.Header)

	return clone
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

	// Normalize headers before validation to handle duplicate headers
	// according to HTTP standards (combine with commas except for special headers)
	normalizedReq := cloneRequestWithNormalizedHeaders(r)

	// Validate request with normalized headers
	requestValidationInput := &openapi3filter.RequestValidationInput{
		Request:    normalizedReq,
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
		return fmt.Errorf("request validation error: %w", err), errResponseCode
	}

	// Handle Success
	return nil, http.StatusOK
}
