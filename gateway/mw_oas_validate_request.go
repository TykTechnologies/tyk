package gateway

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/httputil"
	"github.com/TykTechnologies/tyk/pkg/schema"

	tykregexp "github.com/TykTechnologies/tyk/regexp"
)

var (
	skipHeaderNormalization = map[string]bool{
		header.SetCookie:        true,
		header.ContentLength:    true,
		header.TransferEncoding: true,
		header.Host:             true,
	}
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
	// For APIs with mux-template listen paths (e.g., /api/{version:.*}), we fall back
	// to the original findOperation behavior because StripListenPath doesn't work reliably
	// with such patterns - they can greedily match parts of the OAS path.
	if httputil.IsMuxTemplate(k.Spec.Proxy.ListenPath) {
		return k.processRequestWithFindOperation(r)
	}

	// Use FindSpecMatchesStatus to check if this path should be validated
	// This ensures the standard regex-based path matching is used, respecting gateway configurations
	versionInfo, _ := k.Spec.Version(r)
	versionPaths := k.Spec.RxPaths[versionInfo.Name]

	urlSpec, found := k.Spec.FindSpecMatchesStatus(r, versionPaths, OASValidateRequest)

	if !found || urlSpec == nil {
		// No validation configured for this path
		return nil, http.StatusOK
	}

	// If this URLSpec has multiple candidates (collapsed parameterized paths),
	// disambiguate using path parameter schema validation.
	if len(urlSpec.OASValidateRequestCandidates) > 0 {
		return k.processRequestWithCandidates(r, urlSpec)
	}

	validateRequest := urlSpec.OASValidateRequestMeta
	if validateRequest == nil || !validateRequest.Enabled {
		return nil, http.StatusOK
	}

	errResponseCode := http.StatusUnprocessableEntity
	if validateRequest.ErrorResponseCode != 0 {
		errResponseCode = validateRequest.ErrorResponseCode
	}

	normalizeHeaders(r.Header)

	// Find the route using the OAS path from URLSpec, not the actual request path.
	// This allows prefix/suffix matching to work: request to /anything/abc can be
	// validated against the /anything operation.
	// We pass both the stripped path (for path param extraction) and full path (for regexp listen paths).
	strippedPath := k.Spec.StripListenPath(r.URL.Path)
	route, pathParams, err := k.Spec.findRouteForOASPath(urlSpec.OASPath, urlSpec.OASMethod, strippedPath, r.URL.Path)
	if err != nil || route == nil {
		log.WithFields(logrus.Fields{
			"method":   r.Method,
			"path":     r.URL.Path,
			"oas_path": urlSpec.OASPath,
			"error":    err,
		}).Error("OAS ValidateRequest: could not find route for matched OAS path")
		return fmt.Errorf("request validation error: no matching operation was found for request: %s %s", r.Method, r.URL.Path), errResponseCode
	}

	// Validate request
	requestValidationInput := &openapi3filter.RequestValidationInput{
		Request:    r,
		PathParams: pathParams,
		Route:      route,
		Options: &openapi3filter.Options{
			AuthenticationFunc: func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
				return nil
			},
		},
	}

	err = openapi3filter.ValidateRequest(r.Context(), requestValidationInput)
	if err != nil {
		return fmt.Errorf("request validation error: %w", schema.RestoreUnicodeEscapesInError(err)), errResponseCode
	}

	// Handle Success
	return nil, http.StatusOK
}

// processRequestWithCandidates handles validation when multiple OAS endpoints collapse
// to the same regex pattern (e.g., /employees/{prct} and /employees/{zd} both become
// /employees/([^/]+)). Candidates are sorted most-restrictive-first. For each candidate:
//   - Phase 1: check if the path parameter values satisfy the candidate's path param schemas.
//   - Phase 2: if path params match, commit to this candidate and run full validation.
//     Do NOT fall through to less restrictive candidates.
//
// This prevents a catch-all type:string candidate from stealing requests that belong to
// a more restrictive type:number candidate.
func (k *ValidateRequest) processRequestWithCandidates(r *http.Request, urlSpec *URLSpec) (error, int) {
	normalizeHeaders(r.Header)
	strippedPath := k.Spec.StripListenPath(r.URL.Path)

	for _, candidate := range urlSpec.OASValidateRequestCandidates {
		if candidate.OASValidateRequestMeta == nil || !candidate.OASValidateRequestMeta.Enabled {
			continue
		}

		// Look up the path item directly from the OAS spec instead of using the OAS
		// router, which cannot distinguish between structurally identical paths.
		pathItem := k.Spec.OAS.Paths.Value(candidate.OASPath)
		if pathItem == nil {
			continue
		}
		operation := pathItem.GetOperation(candidate.OASMethod)
		if operation == nil {
			continue
		}

		pathParams := extractPathParams(candidate.OASPath, strippedPath)

		// Phase 1: validate path parameters against this candidate's schemas.
		// If they don't match, skip to the next candidate.
		if !pathParamsMatchOperation(pathParams, operation) {
			continue
		}

		// Phase 2: path params matched — commit to this candidate. Run full validation
		// and return the result regardless of success/failure. Do not fall through.
		route := &routers.Route{
			Spec:      &k.Spec.OAS.T,
			Path:      candidate.OASPath,
			PathItem:  pathItem,
			Method:    candidate.OASMethod,
			Operation: operation,
		}

		errResponseCode := http.StatusUnprocessableEntity
		if candidate.OASValidateRequestMeta.ErrorResponseCode != 0 {
			errResponseCode = candidate.OASValidateRequestMeta.ErrorResponseCode
		}

		requestValidationInput := &openapi3filter.RequestValidationInput{
			Request:    r,
			PathParams: pathParams,
			Route:      route,
			Options: &openapi3filter.Options{
				AuthenticationFunc: func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
					return nil
				},
			},
		}

		err := openapi3filter.ValidateRequest(r.Context(), requestValidationInput)
		if err != nil {
			return fmt.Errorf("request validation error: %w", schema.RestoreUnicodeEscapesInError(err)), errResponseCode
		}
		return nil, http.StatusOK
	}

	// No candidate's path params matched at all.
	errResponseCode := http.StatusUnprocessableEntity
	for _, candidate := range urlSpec.OASValidateRequestCandidates {
		if candidate.OASValidateRequestMeta != nil && candidate.OASValidateRequestMeta.ErrorResponseCode != 0 {
			errResponseCode = candidate.OASValidateRequestMeta.ErrorResponseCode
			break
		}
	}

	return fmt.Errorf("request validation error: path parameter doesn't match any endpoint"), errResponseCode
}

// pathParamsMatchOperation checks whether the given path parameter values satisfy
// the path parameter schemas defined in the OAS operation. This is used as a quick
// pre-filter before committing to full request validation.
func pathParamsMatchOperation(pathParams map[string]string, operation *openapi3.Operation) bool {
	for _, paramRef := range operation.Parameters {
		if paramRef == nil || paramRef.Value == nil || paramRef.Value.In != "path" {
			continue
		}
		param := paramRef.Value
		if param.Schema == nil || param.Schema.Value == nil {
			continue
		}

		value, exists := pathParams[param.Name]
		if !exists {
			return false
		}

		// For type:number/integer, attempt to parse as float to match kin-openapi behavior.
		// For type:string (no constraints), this always passes — that's expected,
		// the candidate ordering ensures more restrictive types are checked first.
		s := param.Schema.Value
		if s.Type != nil {
			if s.Type.Is("number") || s.Type.Is("integer") {
				if _, err := strconv.ParseFloat(value, 64); err != nil {
					return false
				}
			} else if s.Type.Is("boolean") {
				if _, err := strconv.ParseBool(value); err != nil {
					return false
				}
			}
		}

		// Check pattern constraint if present.
		if s.Pattern != "" {
			matched, err := tykregexp.MatchString(s.Pattern, value)
			if err != nil || !matched {
				return false
			}
		}

		// Check enum constraint if present.
		if len(s.Enum) > 0 {
			found := false
			for _, e := range s.Enum {
				if fmt.Sprintf("%v", e) == value {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

// processRequestWithFindOperation is the original implementation that uses findOperation
// to locate the OAS route. This is used for APIs with mux-template listen paths where
// the standard regex-based path matching doesn't work reliably.
func (k *ValidateRequest) processRequestWithFindOperation(r *http.Request) (error, int) {
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

	normalizeHeaders(r.Header)

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
		return fmt.Errorf("request validation error: %w", schema.RestoreUnicodeEscapesInError(err)), errResponseCode
	}

	// Handle Success
	return nil, http.StatusOK
}

// normalizeHeaders prepares HTTP headers for OpenAPI validation by joining multiple values with commas.
// Headers in the skipHeaderNormalization map are excluded from this process.
func normalizeHeaders(headers http.Header) {
	for key, values := range headers {
		if !skipHeaderNormalization[key] && len(values) > 1 {
			if key == header.Cookie {
				headers[key] = []string{strings.Join(values, "; ")}
			} else {
				headers[key] = []string{strings.Join(values, ",")}
			}
		}
	}
}
