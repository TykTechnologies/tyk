package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

func OasAPIS(r *openapi3.Reflector) error {
	return getListOfOASApisRequest(r)
}

func getListOfOASApisRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/apis/oas")
	if err != nil {
		return err
	}
	// TODO:: ADD MODE query parameter
	oc.AddRespStructure(new([]oas.OAS))
	oc.SetID("listApisOAS")
	oc.SetTags("OAS APIs")
	oc.SetSummary("List all OAS  format APIS")
	oc.SetDescription("List all OAS format APIs, when used without the Tyk Dashboard.")
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	return r.AddOperation(oc)
}

func getOASApiRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/apis/oas/{apiID}")
	if err != nil {
		return err
	}
	oc.AddRespStructure(new(oas.OAS))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	oc.SetTags("APIs")
	oc.SetID("getApi")
	oc.SetDescription("Get API definition\n        Only if used without the Tyk Dashboard")
	return r.AddOperation(oc)
}
