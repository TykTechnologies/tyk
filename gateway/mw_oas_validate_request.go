package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/paramextractor"
	"github.com/TykTechnologies/tyk/internal/reflect"
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

func (k *ValidateRequest) newParamExtractor() paramextractor.Extractor {
	opt := k.Gw.GetConfig().HttpServerOptions
	return paramextractor.NewParamExtractorFromFlags(
		opt.EnablePathPrefixMatching,
		opt.EnablePathSuffixMatching,
	)
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *ValidateRequest) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
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

	pathParams, err := k.newParamExtractor().Extract(r, validateRequest.path)
	if err != nil {
		log.
			WithError(err).
			WithFields(logrus.Fields{
				"path":    r.URL.Path,
				"pattern": validateRequest.path,
				"method":  r.Method,
			}).
			Error("Parameter extraction failed")

		return fmt.Errorf("param extraction error: %w", err), http.StatusInternalServerError
	}

	// Validate request
	requestValidationInput := &openapi3filter.RequestValidationInput{
		Request:    r,
		PathParams: pathParams,
		Route:      reflect.Clone(validateRequest.route),
		Options: &openapi3filter.Options{
			AuthenticationFunc: func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
				return nil
			},
		},
	}

	err = openapi3filter.ValidateRequest(r.Context(), requestValidationInput)
	if err != nil {
		return fmt.Errorf("request validation error: %w", err), errResponseCode
	}

	// Handle Success
	return nil, http.StatusOK
}
