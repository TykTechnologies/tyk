package swagger

import (
	"errors"
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/gateway"
)

var ErrOperationExposer = errors.New("object is not of type openapi3.OperationExposer")

const (
	APIsTag    = "APIs"
	ApiTagDesc = `**Note: Applies only to Tyk Gateway Community Edition** <br/>

API Management is very simple using the Tyk REST API: each update only affects the underlying file, and this endpoint will only work with disk based installations, not Database-backed ones.<br/>

APIs that are added this way are flushed to to disk into the app_path folder using the format: *{api-id}.json*. Updating existing APIs that use a different naming convention will cause those APIs to be added, which could subsequently lead to a loading error and crash if they use the same listen_path. <br/>

These methods only work on a single API node. If updating a cluster, it is important to ensure that all nodes are updated before initiating a reload.<br/>
`
)

func APIS(r *openapi3.Reflector) error {
	addTag(APIsTag, ApiTagDesc)
	return addOperations(r, getClassicApiRequest, deleteClassicApiRequest, putClassicApiRequest, getListOfClassicApisRequest, createClassicApiRequest)
}

// Done
func getClassicApiRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/apis/{apiID}")
	if err != nil {
		return err
	}
	oc.AddRespStructure(new(apidef.APIDefinition), func(cu *openapi.ContentUnit) {
		cu.Description = "API definition"
	})
	statusNotFound(oc, "Api not found")
	forbidden(oc)
	oc.SetTags(APIsTag)
	oc.SetID("getApi")
	oc.SetSummary("Get API definition with ID")
	oc.SetDescription("Get API definition\n        Only if used without the Tyk Dashboard")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	o3.Operation().WithParameters(apIIDParameter())
	oc.SetDescription("Get API definition\n        Only if used without the Tyk Dashboard")
	err = r.AddOperation(oc)
	if err != nil {
		return err
	}
	addNewResponseHeader(o3, http.StatusOK, HeaderCr{
		Key:         "x-tyk-base-api-id",
		Description: "ID of the base API if the requested API is a version.",
		Type:        openapi3.SchemaTypeString,
	})
	return nil
}

// Done
func getListOfClassicApisRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/apis")
	if err != nil {
		return err
	}
	oc.AddRespStructure(new([]apidef.APIDefinition), func(cu *openapi.ContentUnit) {
		cu.Description = "List of API definitions"
	})
	oc.SetID("listApis")
	oc.SetDescription(" List APIs\n         Only if used without the Tyk Dashboard")
	oc.SetSummary("Get list of apis")
	oc.SetTags(APIsTag)
	forbidden(oc)
	return r.AddOperation(oc)
}

// Done
func putClassicApiRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPut, "/tyk/apis/{apiID}")
	if err != nil {
		return err
	}
	oc.AddReqStructure(new(apidef.APIDefinition))
	oc.AddRespStructure(new(apiModifyKeySuccess), func(cu *openapi.ContentUnit) {
		cu.Description = "API updated"
	})
	oc.SetID("updateApi")
	oc.SetSummary("Updating an API definition  with its ID")
	oc.SetDescription("Updating an API definition uses the same signature an object as a `POST`, however it will first ensure that the API ID that is being updated is the same as the one in the object being `PUT`.\n\n\n        Updating will completely replace the file descriptor and will not change an API Definition that has already been loaded, the hot-reload endpoint will need to be called to push the new definition to live.")
	oc.SetTags(APIsTag)
	statusNotFound(oc, "An Api with the specified ApiID was not found.")
	statusBadRequest(oc, "Bad request.Sending a ApiID for an OAs api or apiID in path does not match the one in the body.")
	statusInternalServerError(oc, "Unexpected error.")
	forbidden(oc)
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	o3.Operation().WithParameters(apIIDParameter())
	return r.AddOperation(oc)
}

// Done
func deleteClassicApiRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodDelete, "/tyk/apis/{apiID}")
	if err != nil {
		return err
	}
	oc.SetTags(APIsTag)
	oc.SetID("deleteApi")
	oc.SetDescription("Deleting an API definition will remove the file from the file store, the API definition will NOT be unloaded, a separate reload request will need to be made to disable the API endpoint.")
	oc.SetSummary("Deleting an API definition with ID")
	oc.AddRespStructure(new(apiModifyKeySuccess), func(cu *openapi.ContentUnit) {
		cu.Description = "API deleted"
	})
	statusNotFound(oc, "An Api with the specified ApiID was not found.")
	statusInternalServerError(oc, "Unexpected error.")
	forbidden(oc)
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	o3.Operation().WithParameters(apIIDParameter())
	return r.AddOperation(oc)
}

// Done
func createClassicApiRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/apis")
	if err != nil {
		return err
	}
	oc.SetTags(APIsTag)
	oc.SetID("createApi")
	oc.SetDescription(" Create API\n         A single Tyk node can have its API Definitions queried, deleted and updated remotely. This functionality enables you to remotely update your Tyk definitions without having to manage the files manually.")
	oc.SetSummary("Creat an API")
	oc.AddReqStructure(new(apidef.APIDefinition))
	oc.AddRespStructure(new(apiModifyKeySuccess), openapi.WithHTTPStatus(http.StatusOK))
	statusInternalServerError(oc, "Unexpected error.")
	forbidden(oc)
	statusBadRequest(oc, "Returned when you send a malformed body or when the request body fails validation")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	o3.Operation().WithParameters(addApiPostQueryParam()...)
	return r.AddOperation(oc)
}

// Done
func getApiVersions(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/apis/{apiID}/versions")
	if err != nil {
		return err
	}
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	oc.AddRespStructure(new(gateway.VersionMetas), func(cu *openapi.ContentUnit) {
		cu.Description = "API version metas"
	})
	statusNotFound(oc, "API not found")
	forbidden(oc)
	oc.SetID("listApiVersions")
	oc.SetTags(APIsTag)
	oc.SetSummary("Listing versions of an API")
	oc.SetDescription("Listing versions of an API")
	o3.Operation().WithParameters(apIIDParameter(), searchTextQuery(), accessTypeQuery())
	return r.AddOperation(oc)
}

func apIIDParameter() openapi3.ParameterOrRef {
	var example interface{} = "keyless"
	return openapi3.Parameter{Description: StringPointerValue("The API ID"), In: openapi3.ParameterInPath, Example: &example, Name: "apiID", Required: &isRequired, Schema: stringSchema()}.ToParameterOrRef()
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

func searchTextQuery() openapi3.ParameterOrRef {
	return openapi3.Parameter{Description: StringPointerValue("Search for API version name"), In: openapi3.ParameterInQuery, Name: "searchText", Required: &isOptional, Schema: stringSchema()}.ToParameterOrRef()
}

func accessTypeQuery() openapi3.ParameterOrRef {
	return openapi3.Parameter{Description: StringPointerValue("Filter for internal or external API versions"), In: openapi3.ParameterInQuery, Name: "accessType", Required: &isOptional, Schema: stringEnumSchema("internal", "external")}.ToParameterOrRef()
}
