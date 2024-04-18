package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/gateway"
)

const OASTag = "OAS APIs"

func OasAPIS(r *openapi3.Reflector) error {
	return addOperations(r, getListOfOASApisRequest, postOAsApi, apiOASExportHandler, getOASApiRequest, apiOASPutHandler, deleteOASHandler, apiOASExportWithIDHandler, importApiOASPostHandler, oasVersionsHandler, apiOASPatchHandler)
}

func getListOfOASApisRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/apis/oas")
	if err != nil {
		return err
	}
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	//TODO
	///recommended i use external reference just incase it is updated
	par := []openapi3.ParameterOrRef{oasModeQuery("Mode of OAS get, by default mode could be empty which means to get OAS spec including OAS Tyk extension. \n When mode=public, OAS spec excluding Tyk extension will be returned in the response")}
	o3.Operation().WithParameters(par...)
	oc.AddRespStructure(new([]oas.OAS), openapi.WithHTTPStatus(http.StatusOK), func(cu *openapi.ContentUnit) {
		cu.Description = "List of API definitions in OAS format"
	})
	oc.SetID("listApisOAS")
	oc.SetTags(OASTag)
	oc.SetSummary("List all OAS format APIS")
	oc.SetDescription("List all OAS format APIs, when used without the Tyk Dashboard.")
	forbidden(oc)
	return r.AddOperation(oc)
}

func postOAsApi(r *openapi3.Reflector) error {
	// TODO::Should this be external reference or should we create a local object.
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/apis/oas")
	if err != nil {
		return err
	}
	oc.SetTags(OASTag)
	statusBadRequest(oc, "Malformed API data")
	forbidden(oc)
	statusInternalServerError(oc, "Unexpected error")
	oc.AddRespStructure(new(apiModifyKeySuccess), func(cu *openapi.ContentUnit) {
		cu.Description = "API created"
	})
	oc.SetID("createApiOAS")
	oc.SetDescription(" Create API with OAS format\n         A single Tyk node can have its API Definitions queried, deleted and updated remotely. This functionality enables you to remotely update your Tyk definitions without having to manage the files manually.")
	oc.SetSummary("Create API with OAS format")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	o3.Operation().WithParameters(addApiPostQueryParam()...)
	return r.AddOperation(oc)
}

func apiOASExportHandler(r *openapi3.Reflector) error {
	///TODO:: should  Content-Disposition be added as headers
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/apis/oas/export")
	if err != nil {
		return err
	}
	oc.SetID("downloadApisOASPublic")
	oc.SetSummary("Download all OAS format APIs")
	oc.SetDescription("Download all OAS format APIs, when used without the Tyk Dashboard.")
	oc.SetTags(OASTag)
	oc.AddRespStructure(new(string), openapi.WithContentType("application/octet-stream"), func(cu *openapi.ContentUnit) {
		cu.Description = "Get list of oas API definition"
	})
	forbidden(oc)
	statusInternalServerError(oc, "Unexpected error")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{oasModeQuery("Mode of OAS get, by default mode could be empty which means to get OAS spec including OAS Tyk extension. \n When mode=public, OAS spec excluding Tyk extension will be returned in the response")}
	o3.Operation().WithParameters(par...)
	err = r.AddOperation(oc)
	if err != nil {
		return err
	}
	addBinaryFormat(o3, http.StatusOK)
	return nil
}

// Done
func getOASApiRequest(r *openapi3.Reflector) error {
	// TODO::response of this is different from previous
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/apis/oas/{apiID}")
	if err != nil {
		return err
	}
	oc.AddRespStructure(new(oas.OAS), func(cu *openapi.ContentUnit) {
		cu.Description = "Api fetched successfully"
	})
	forbidden(oc)
	statusNotFound(oc, "API not found")
	statusBadRequest(oc, "trying to access an API whose definition is in Tyk classic format")
	oc.SetTags(OASTag)
	oc.SetID("getOASApi")
	oc.SetSummary("Get OAS Api definition")
	oc.SetDescription("Get OAS Api definition\n  using the api Id")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{apIIDParameter(), oasModeQuery("Mode of OAS get, by default mode could be empty which means to get OAS spec including OAS Tyk extension. \n When mode=public, OAS spec excluding Tyk extension will be returned in the response")}
	o3.Operation().WithParameters(par...)
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
func apiOASPutHandler(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPut, "/tyk/apis/oas/{apiID}")
	if err != nil {
		return err
	}
	forbidden(oc)
	statusInternalServerError(oc, "Unexpected error")
	statusBadRequest(oc, "Malformed Request or trying to update api in tyk classic format")
	statusNotFound(oc, "API not found")
	oc.AddRespStructure(new(apiModifyKeySuccess), openapi.WithHTTPStatus(http.StatusOK), func(cu *openapi.ContentUnit) {
		cu.Description = "API updated"
	})
	oc.AddReqStructure(new(oas.OAS))
	oc.SetID("updateApiOAS")
	oc.SetSummary("Update OAS API definition")
	oc.SetDescription("Updating an API definition uses the same signature an object as a `POST`, however it will first ensure that the API ID that is being updated is the same as the one in the object being `PUT`.\n\n\n        Updating will completely replace the file descriptor and will not change an API Definition that has already been loaded, the hot-reload endpoint will need to be called to push the new definition to live.")
	oc.SetTags(OASTag)
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{apIIDParameter()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func apiOASExportWithIDHandler(r *openapi3.Reflector) error {
	///TODO:: should we add Content-Disposition headers
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/apis/oas/{apiID}/export")
	if err != nil {
		return err
	}
	oc.AddRespStructure(new(string), openapi.WithContentType(applicationOctetStream), func(cu *openapi.ContentUnit) {
		cu.Description = "Exported API definition file"
	})
	statusInternalServerError(oc, "Unexpected error")
	statusBadRequest(oc, "requesting API definition that is in Tyk classic format")
	statusNotFound(oc, "API not found")
	forbidden(oc)
	oc.SetSummary("Download an OAS format APIs, when used without the Tyk Dashboard.")
	oc.SetDescription("Mode of OAS export, by default mode could be empty which means to export OAS spec including OAS Tyk extension. \n  When mode=public, OAS spec excluding Tyk extension is exported")
	oc.SetTags(OASTag)
	oc.SetID("downloadApiOASPublic")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{apIIDParameter(), oasModeQuery()}
	o3.Operation().WithParameters(par...)
	err = r.AddOperation(oc)
	if err != nil {
		return err
	}
	addBinaryFormat(o3, http.StatusOK)
	return nil
}

func importApiOASPostHandler(r *openapi3.Reflector) error {
	///TODO:: check if the OAs post query parameters can be applied here.
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/apis/oas/import")
	if err != nil {
		return err
	}
	oc.SetTags(OASTag)
	oc.SetSummary("Create a new OAS format API, without x-tyk-gateway")
	oc.SetID("importOAS")
	forbidden(oc)
	oc.AddRespStructure(new(apiModifyKeySuccess), func(cu *openapi.ContentUnit) {
		cu.Description = "API definition created"
	})
	oc.AddReqStructure(new(oas.OAS), func(cu *openapi.ContentUnit) {
	})

	oc.SetDescription("Create a new OAS format API, without x-tyk-gateway.\n        For use with an existing OAS API that you want to expose via your Tyk Gateway. (New)")
	statusInternalServerError(oc, "Unexpected error")
	statusBadRequest(oc, "Malformed request or when the payload contain x-tyk-api-gateway")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	o3.Operation().WithParameters(patchAndImportQueryParameters(true)...)
	return r.AddOperation(oc)
}

// Done
func oasVersionsHandler(r *openapi3.Reflector) error {
	// TODO::in previous api this was wrong
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/apis/oas/{apiID}/versions")
	if err != nil {
		return err
	}
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	statusNotFound(oc, "API not found")
	forbidden(oc)
	oc.SetID("listOASApiVersions")
	oc.SetDescription("Listing versions of an OAS API")
	oc.AddRespStructure(new(gateway.VersionMetas), func(cu *openapi.ContentUnit) {
		cu.Description = "API version metas"
	})
	oc.SetSummary("Listing versions of an OAS API")
	oc.SetTags(OASTag)
	o3.Operation().WithParameters(apIIDParameter(), searchTextQuery(), accessTypeQuery())

	return r.AddOperation(oc)
}

// /Done
func deleteOASHandler(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodDelete, "/tyk/apis/oas/{apiID}")
	if err != nil {
		return err
	}
	forbidden(oc)
	statusInternalServerError(oc, "When delete request is sent while using dashboard app configs")
	statusBadRequest(oc, "API ID not specified")
	statusNotFound(oc, "API not found")
	oc.AddRespStructure(new(apiModifyKeySuccess), func(cu *openapi.ContentUnit) {
		cu.Description = "API deleted"
	})
	oc.SetID("deleteOASApi")
	oc.SetSummary("Deleting an OAS API")
	oc.SetDescription("Deleting an API definition will remove the file from the file store, the API definition will NOT be unloaded, a separate reload request will need to be made to disable the API endpoint.")
	oc.SetTags(OASTag)
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{apIIDParameter()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func apiOASPatchHandler(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPatch, "/tyk/apis/oas/{apiID}")
	if err != nil {
		return err
	}
	oc.AddReqStructure(new(oas.OAS))
	statusInternalServerError(oc, "Unexpected error")
	statusBadRequest(oc, "Malformed request")
	statusNotFound(oc, "API not found")
	oc.AddRespStructure(new(apiModifyKeySuccess), func(cu *openapi.ContentUnit) {
		cu.Description = "API patched"
	})
	oc.SetSummary("Patch API with OAS format.")
	oc.SetDescription("Update API with OAS format. You can use this endpoint to update OAS part of the tyk API definition.\n        This endpoint allows you to configure tyk OAS extension based on query params provided(similar to import)")
	oc.SetTags(OASTag)
	oc.SetID("patchApiOAS")

	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{apIIDParameter()}
	par = append(par, patchAndImportQueryParameters(false)...)
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func oasModeQuery(description ...string) openapi3.ParameterOrRef {
	stringType := openapi3.SchemaTypeString
	desc := "Can be set to public"
	var example interface{} = "public"
	if len(description) != 0 {
		desc = description[0]
	}
	return openapi3.Parameter{
		In: openapi3.ParameterInQuery, Name: "mode", Example: &example, Required: &isOptional, Description: &desc, Schema: &openapi3.SchemaOrRef{
			Schema: &openapi3.Schema{
				Type: &stringType,
				Enum: []interface{}{"public"},
			},
		},
	}.ToParameterOrRef()
}

type BinarySchema struct {
	Name string `json:"name"`
}

func patchAndImportQueryParameters(includeApiID bool) []openapi3.ParameterOrRef {
	par := []openapi3.ParameterOrRef{
		createParameter(ParameterValues{
			Name:        "upstreamURL",
			Description: "Upstream URL for the API",
		}),
		createParameter(ParameterValues{
			Name:        "listenPath",
			Description: "Listen path for the API",
		}),
		createParameter(ParameterValues{
			Name:        "customDomain",
			Description: "Custom domain for the API",
		}),
		createParameter(ParameterValues{
			Name:        "authentication",
			Type:        openapi3.SchemaTypeBoolean,
			Description: "Enable or disable authentication in your Tyk Gateway as per your OAS document.",
		}),
		createParameter(ParameterValues{
			Name:        "validateRequest",
			Type:        openapi3.SchemaTypeBoolean,
			Description: "Enable validateRequest middleware for all endpoints having a request body with media type application/json",
		}),
		createParameter(ParameterValues{
			Name:        "allowList",
			Description: "Enable allowList middleware for all endpoints",
			Type:        openapi3.SchemaTypeBoolean,
		}),
		createParameter(ParameterValues{
			Name:        "mockResponse",
			Description: "Enable mockResponse middleware for all endpoints having responses configured.",
			Type:        openapi3.SchemaTypeBoolean,
		}),
	}
	if includeApiID {
		par = append(par, createParameter(ParameterValues{
			Name:        "apiID",
			Description: "ID of the API",
		}))
	}
	return par
}
