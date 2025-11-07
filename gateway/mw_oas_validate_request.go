package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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
	operation := k.Spec.findOperation(r) // todo: remove it
	// todo: I need to write params extractor
	// it should be hidden behind interface with one exposed method Extract(r *http.Request, path string) (map[string]string, error)
	// prefix, suffix cfg flags suggest that I need to implement 4 (or 3) extractors
	// 1. strict -> split segments and start iteration all the segments and look for  patterns in segments like {param}
	// 2. prefix -> technically the same like strict bul does not expect that number of segments in pattern and sample are equal
	// 3. suffix -> like prefix
	// 4. glob -> pattern has to be placed in re capture group. capture group should be extracted, after extraction salgorithm from strict matching can be used. to properly detect it we need initial pattern or item path, so Extract() method signature can be changed :p

	version, _ := k.Spec.Version(r)
	versionPaths := k.Spec.RxPaths[version.Name]
	found, meta := k.Spec.CheckSpecMatchesStatus(r, versionPaths, OasMock)

	if !found {
		return nil, http.StatusOK
	}

	validateRequest, ok := meta.(*oasValidateMiddleware)
	if !ok {
		return errors.New("unexpected type"), http.StatusInternalServerError
	}

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
		PathParams: operation.pathParams, // todo: remove it
		Route:      operation.route,      // todo: remove it
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
