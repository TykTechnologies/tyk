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
	oc.SetSummary("Get API definition with ID")
	oc.SetDescription("Get API definition\n        Only if used without the Tyk Dashboard")
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
	oc.SetSummary("Get list of apis")
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
	oc.SetSummary("Updating an API definition  with its ID")
	oc.SetDescription("Updating an API definition uses the same signature an object as a `POST`, however it will first ensure that the API ID that is being updated is the same as the one in the object being `PUT`.\n\n\n        Updating will completely replace the file descriptor and will not change an API Definition that has already been loaded, the hot-reload endpoint will need to be called to push the new definition to live.")
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
	oc.SetDescription("Deleting an API definition will remove the file from the file store, the API definition will NOT be unloaded, a separate reload request will need to be made to disable the API endpoint.")
	oc.SetSummary("Deleting an API definition with ID")
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
	oc.SetDescription(" Create API\n         A single Tyk node can have its API Definitions queried, deleted and updated remotely. This functionality enables you to remotely update your Tyk definitions without having to manage the files manually.")
	oc.SetSummary("Creat an API")
	oc.AddReqStructure(new(apidef.APIDefinition))
	oc.AddRespStructure(new(apiModifyKeySuccess), openapi.WithHTTPStatus(http.StatusOK))
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
	return openapi3.Parameter{In: openapi3.ParameterInPath, Name: "apiID", Required: &isRequired, Schema: stringSchema()}.ToParameterOrRef()
}

func addApiPostQueryParam() []openapi3.ParameterOrRef {
	baseApiIdDesc := "The base API which the new version will be linked to."
	baseApiVersionNameDesc := "The version name of the base API while creating the first version. This doesn't have to be sent for the next versions but if it is set, it will override base API version name."
	newVersionNameDesc := "The version name of the created version."
	setVersionDesc := "If true, the new version is set as default version."
	return []openapi3.ParameterOrRef{
		openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "base_api_id", Schema: stringSchema(), Description: &baseApiIdDesc}.ToParameterOrRef(),

		openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "base_api_version_name", Schema: stringSchema(), Description: &baseApiVersionNameDesc}.ToParameterOrRef(),
		openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "new_version_name", Schema: stringSchema(), Description: &newVersionNameDesc}.ToParameterOrRef(),
		openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "set_default", Schema: boolSchema(), Description: &setVersionDesc}.ToParameterOrRef(),
	}
}
