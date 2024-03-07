package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
)

func APIS(r *openapi3.Reflector) error {
	err := getClassicApiRequest(r)
	if err != nil {
		return err
	}
	err = deleteClassicApiRequest(r)
	if err != nil {
		return err
	}

	return putClassicApiRequest(r)
}

func getClassicApiRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/apis/{apiID}")
	if err != nil {
		return err
	}
	oc.AddReqStructure(new(apidef.APIDefinition))
	oc.AddRespStructure(new(apidef.APIDefinition))
	oc.SetTags("APIs")
	oc.SetID("getApi")
	return r.AddOperation(oc)
}

func putClassicApiRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPut, "/tyk/apis/{apiID}")
	if err != nil {
		return err
	}
	oc.AddReqStructure(new(apidef.APIDefinition))
	oc.AddRespStructure(new(apiModifyKeySuccess))
	oc.SetID("updateApi")
	oc.SetTags("APIs")
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	return r.AddOperation(oc)
}

func deleteClassicApiRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodDelete, "/tyk/apis/{apiID}")
	if err != nil {
		return err
	}
	oc.AddReqStructure(new(apidef.APIDefinition))
	oc.SetTags("APIs")
	oc.SetID("deleteApi")
	oc.AddRespStructure(new(apiModifyKeySuccess))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	return r.AddOperation(oc)
}
