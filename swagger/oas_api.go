package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

const OASTag = "OAS APIs"

func OasAPIS(r *openapi3.Reflector) error {
	return addOperations(r, getListOfOASApisRequest, postOAsApi, apiOASExportHandler, getOASApiRequest, apiOASPutHandler)
}

func getListOfOASApisRequest(r *openapi3.Reflector) error {
	// TODO::check response header for this
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/apis/oas")
	if err != nil {
		return err
	}
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
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
	statusInternalServerError(oc, "Due to enabled use_db_app_configs, please use the Dashboard API")
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
	// TODO::This is super wrong because of doJSONExport as it returns  application/octet-stream
	// TODO::I should ask about it.
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/apis/oas/export")
	if err != nil {
		return err
	}
	oc.SetID("downloadApisOASPublic")
	oc.SetSummary("Download all OAS format APIs")
	oc.SetDescription("Download all OAS format APIs, when used without the Tyk Dashboard.")
	oc.SetTags(OASTag)
	oc.AddRespStructure(new([]oas.OAS), openapi.WithContentType("application/octet-stream"), func(cu *openapi.ContentUnit) {
		cu.Description = "Get list of oas API definition"
	})
	forbidden(oc)
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{oasModeQuery("Mode of OAS get, by default mode could be empty which means to get OAS spec including OAS Tyk extension. \n When mode=public, OAS spec excluding Tyk extension will be returned in the response")}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func getOASApiRequest(r *openapi3.Reflector) error {
	// TODO::response of this is different from previous
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/apis/oas/{apiID}")
	if err != nil {
		return err
	}
	oc.AddRespStructure(new(oas.OAS), func(cu *openapi.ContentUnit) {
		cu.Description = "Api fetched successfully"
		// todo figure out to fix this and add new headers
		cu.SetFieldMapping(openapi.InHeader, map[string]string{
			"x-tyk-base-api-id": "x-tyk-base-api-id",
		})
	})
	forbidden(oc)
	statusNotFound(oc, "API not found")
	statusBadRequest(oc, "the requested API definition is in Tyk classic format, please use old api endpoint")
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
	return r.AddOperation(oc)
}

func apiOASPutHandler(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPut, "/tyk/apis/oas/{apiID}")
	if err != nil {
		return err
	}
	statusInternalServerError(oc, "Due to enabled use_db_app_configs, please use the Dashboard API")
	statusBadRequest(oc, "Must specify an apiID to update ")
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

func oasModeQuery(description ...string) openapi3.ParameterOrRef {
	stringType := openapi3.SchemaTypeString
	desc := "Can be set to public"
	if len(description) != 0 {
		desc = description[0]
	}
	return openapi3.Parameter{
		In: openapi3.ParameterInQuery, Name: "mode", Required: &isOptional, Description: &desc, Schema: &openapi3.SchemaOrRef{
			Schema: &openapi3.Schema{
				Type: &stringType,
				Enum: []interface{}{"public"},
			},
		},
	}.ToParameterOrRef()
}
