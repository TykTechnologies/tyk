package gateway

import (
	"fmt"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"net/http"
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
			return true
		}
	}

	return false
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *ValidateRequest) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	versionInfo, _ := k.Spec.Version(r)
	versionPaths := k.Spec.RxPaths[versionInfo.Name]
	found, _ := k.Spec.CheckSpecMatchesStatus(r, versionPaths, ValidateRequestWithOAS)
	if !found {
		return nil, http.StatusOK
	}

	// replacing servers object to just have listen path so that router.FindRoute(r) will not fail with strict hostname check
	oasSpec := k.Spec.OAS.T
	oasSpec.Servers = openapi3.Servers{
		{URL: k.Spec.Proxy.ListenPath},
	}

	router, err := gorillamux.NewRouter(&oasSpec)
	if err != nil {
		return fmt.Errorf("request validation error: %v", err), http.StatusBadRequest
	}

	route, pathParams, err := router.FindRoute(r)
	if err != nil {
		return fmt.Errorf("request validation error: %v", err), http.StatusBadRequest
	}

	// Validate request
	requestValidationInput := &openapi3filter.RequestValidationInput{
		Request:    r,
		PathParams: pathParams,
		Route:      route,
	}

	err = openapi3filter.ValidateRequestBody(r.Context(), requestValidationInput, route.Operation.RequestBody.Value)
	if err != nil {
		return fmt.Errorf("request validation error: %v", err), http.StatusBadRequest
	}

	// Handle Success
	return nil, http.StatusOK
}
