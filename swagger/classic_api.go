package swagger

import (
	"errors"
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
)

var ErrOperationExposer = errors.New("object is not of type openapi3.OperationExposer")

func APIS(r *openapi3.Reflector) error {
	err := getClassicApiRequest(r)
	if err != nil {
		return err
	}
	err = deleteClassicApiRequest(r)
	if err != nil {
		return err
	}

	err = getListOfClassicApisRequest(r)
	if err != nil {
		return err
	}
	err = createClassicApiRequest(r)
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
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.SetTags("APIs")
	oc.SetID("getApi")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	o3.Operation().WithParameters(apIIDParameter())

	oc.SetDescription("Get API definition\n        Only if used without the Tyk Dashboard")
	return r.AddOperation(oc)
}

func getListOfClassicApisRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/apis")
	if err != nil {
		return err
	}
	oc.AddRespStructure(new([]apidef.APIDefinition))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.SetID("listApis")
	oc.SetDescription(" List APIs\n         Only if used without the Tyk Dashboard")
	oc.SetTags("APIs")
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
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	o3.Operation().WithParameters(apIIDParameter())
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
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	o3.Operation().WithParameters(apIIDParameter())
	return r.AddOperation(oc)
}

func createClassicApiRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/apis")
	if err != nil {
		return err
	}
	oc.SetTags("APIs")
	oc.SetID("createApi")
	oc.AddReqStructure(new(apidef.APIDefinition))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	o3.Operation().WithParameters(addApiPostQueryParam()...)
	return r.AddOperation(oc)
}

func apIIDParameter() openapi3.ParameterOrRef {
	isRequired := true
	return openapi3.Parameter{In: openapi3.ParameterInPath, Name: "apiID", Required: &isRequired}.ToParameterOrRef()
}

func addApiPostQueryParam() []openapi3.ParameterOrRef {
	return []openapi3.ParameterOrRef{
		openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "base_api_id"}.ToParameterOrRef(),
		openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "base_api_version_name"}.ToParameterOrRef(),
		openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "new_version_name"}.ToParameterOrRef(),
		openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "set_default"}.ToParameterOrRef(),
	}
}
