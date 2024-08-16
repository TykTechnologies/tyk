package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/gateway"
)

const (
	APIsTag    = "APIs"
	ApiTagDesc = `**Note: Applies only to Tyk Gateway Community Edition** <br/>

API management is very simple using the Tyk Rest API: each update only affects the underlying file, and this endpoint will only work with disk based installations, not database-backed ones.<br/>

APIs that are added this way are flushed to to disk into the app_path folder using the format: *{api-id}.json*. Updating existing APIs that use a different naming convention will cause those APIs to be added, which could subsequently lead to a loading error and crash if they use the same listen_path. <br/>

These methods only work on a single API node. If updating a cluster, it is important to ensure that all nodes are updated before initiating a reload.<br/>
`
)

func APIS(r *openapi3.Reflector) error {
	addTag(APIsTag, ApiTagDesc, optionalTagParameters{})
	return addOperations(r, getClassicApiRequest, deleteClassicApiRequest, putClassicApiRequest, getListOfClassicApisRequest, createClassicApiRequest, getApiVersions)
}

// Done
func getClassicApiRequest(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodGet,
		PathPattern: "/tyk/apis/{apiID}",
		OperationID: "getApi",
		Tag:         APIsTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	op.AddResponseWithSeparateExample(apidef.APIDefinition{}, http.StatusOK, minimalApis[0], func(cu *openapi.ContentUnit) {
		cu.Description = "API definition."
	})
	op.StatusNotFound("API not found.", func(cu *openapi.ContentUnit) {
		cu.Description = "API not found."
	})
	oc.SetSummary("Get API definition with it's ID.")
	oc.SetDescription("Get API definition from Tyk Gateway.")
	op.AddPathParameter("apiID", "The API ID.", OptionalParameterValues{
		Example: valueToInterface("keyless"),
	})
	op.AddResponseHeaders(ResponseHeader{
		Name:        "x-tyk-base-api-id",
		Description: PointerValue("ID of the base API if the requested API is a version."),
		Type:        PointerValue(openapi3.SchemaTypeString),
	})
	return op.AddOperation()
}

// Done
func getListOfClassicApisRequest(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodGet,
		PathPattern: "/tyk/apis",
		OperationID: "listApis",
		Tag:         APIsTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	op.AddResponseWithSeparateExample(new([]apidef.APIDefinition), http.StatusOK, minimalApis, func(cu *openapi.ContentUnit) {
		cu.Description = "List of API definitions."
	})
	oc.SetDescription("List APIs from Tyk Gateway")
	oc.SetSummary("Get list of apis")
	return op.AddOperation()
}

// Done
func putClassicApiRequest(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodPut,
		PathPattern: "/tyk/apis/{apiID}",
		OperationID: "updateApi",
		Tag:         APIsTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	requestBody := minimalApis[0]
	requestBody.Name = "Update the API name sample"
	requestBody.Proxy.TargetURL = "https://tyk.io/api"
	requestBody.Proxy.ListenPath = "/update-listen-path"
	op.AddReqWithSeparateExample(new(apidef.APIDefinition), requestBody)
	op.AddRespWithExample(
		apiModifyKeySuccess{
			Status: "ok",
			Action: "modified",
			Key:    "1bd5c61b0e694082902cf15ddcc9e6a7",
		}, http.StatusOK, func(cu *openapi.ContentUnit) {
			cu.Description = "API updated."
		})
	oc.SetSummary("Updating an API definition with its ID.")
	oc.SetDescription("Updating an API definition uses the same signature and object as a `POST`, however it will first ensure that the API ID that is being updated is the same as the one in the object being `PUT`.\n\nUpdating will completely replace the file descriptor and will not change an API Definition that has already been loaded, the hot-reload endpoint will need to be called to push the new definition to live.")
	op.StatusNotFound("API not found", func(cu *openapi.ContentUnit) {
		cu.Description = "API not found."
	})
	op.StatusBadRequest("Request malformed")
	op.AddPathParameter("apiID", "The API ID.", OptionalParameterValues{
		Example: valueToInterface("1bd5c61b0e694082902cf15ddcc9e6a7"),
	})
	op.StatusInternalServerError("File object creation failed, write error.")

	return op.AddOperation()
}

// Done
func deleteClassicApiRequest(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodDelete,
		PathPattern: "/tyk/apis/{apiID}",
		OperationID: "deleteApi",
		Tag:         APIsTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	oc.SetDescription("Deleting an API definition will remove the file from the file store, the API definition will NOT be unloaded, a separate reload request will need to be made to disable the API endpoint.")
	oc.SetSummary("Deleting an API definition with ID.")
	op.AddRespWithExample(apiModifyKeySuccess{
		Key:    "1bd5c61b0e694082902cf15ddcc9e6a7",
		Status: "ok",
		Action: "deleted",
	}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "API deleted."
	})

	op.StatusNotFound("API not found", func(cu *openapi.ContentUnit) {
		cu.Description = "API not found."
	})
	op.StatusInternalServerError("Delete failed")
	op.AddPathParameter("apiID", "The API ID.", OptionalParameterValues{
		Example: valueToInterface("1bd5c61b0e694082902cf15ddcc9e6a7"),
	})
	return op.AddOperation()
}

// Done
func createClassicApiRequest(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodPost,
		PathPattern: "/tyk/apis",
		OperationID: "createApi",
		Tag:         APIsTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	oc.SetDescription("Create API. A single Tyk node can have its API Definitions queried, deleted and updated remotely. This functionality enables you to remotely update your Tyk definitions without having to manage the files manually.")
	oc.SetSummary("Creat an API")
	op.AddReqWithSeparateExample(new(apidef.APIDefinition), minimalApis[0])
	op.StatusInternalServerError("file object creation failed, write error")
	op.AddRespWithExample(apiModifyKeySuccess{
		Status: "ok",
		Action: "added",
		Key:    "b84fe1a04e5648927971c0557971565c",
	}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "API created."
	})

	op.StatusBadRequest("Request malformed")
	addApiPostQueryParam(op)
	return op.AddOperation()
}

// Done
func getApiVersions(r *openapi3.Reflector) error {
	oc, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodGet,
		PathPattern: "/tyk/apis/{apiID}/versions",
		OperationID: "listApiVersions",
		Tag:         APIsTag,
	})
	if err != nil {
		return err
	}
	oc.AddPathParameter("apiID", "The API ID.", OptionalParameterValues{
		Example: valueToInterface("keyless"),
	})
	oc.AddRefParameters(SearchText)
	oc.AddRefParameters(AccessType)
	oc.StatusNotFound("API not found", func(cu *openapi.ContentUnit) {
		cu.Description = "API not found."
	})

	versionMetas := gateway.VersionMetas{
		Status: "success",
		Metas: []gateway.VersionMeta{
			{
				ID:               "keyless",
				Name:             "Tyk Test Keyless API",
				VersionName:      "",
				Internal:         false,
				ExpirationDate:   "",
				IsDefaultVersion: false,
			},
			{
				ID:               "1f20d5d2731d47ac9c79fddf826eda00",
				Name:             "Version three Api",
				VersionName:      "v2",
				Internal:         false,
				ExpirationDate:   "",
				IsDefaultVersion: true,
			},
		},
	}

	oc.AddRespWithExample(versionMetas, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "API version metas."
	})
	oc.SetSummary("Listing versions of an API.")
	oc.SetDescription("Listing versions of an API.")

	return oc.AddOperation()
}

func addApiPostQueryParam(oc *OperationWithExample) {
	oc.AddQueryParameter("base_api_id", "The base API which the new version will be linked to.", OptionalParameterValues{
		Example: valueToInterface("663a4ed9b6be920001b191ae"),
	})
	oc.AddQueryParameter("base_api_version_name", "The version name of the base API while creating the first version. This doesn't have to be sent for the next versions but if it is set, it will override base API version name.", OptionalParameterValues{Example: valueToInterface("Default")})
	oc.AddQueryParameter("new_version_name", "The version name of the created version.", OptionalParameterValues{Example: valueToInterface("v2")})
	oc.AddQueryParameter("set_default", "If true, the new version is set as default version.", OptionalParameterValues{Type: openapi3.SchemaTypeBoolean, Example: valueToInterface(true)})
}

var minimalApis = []struct {
	Name       string `json:"name"`
	APIID      string `json:"api_id"`
	OrgID      string `json:"org_id"`
	Definition struct {
		Location string `json:"location"`
		Key      string `json:"key"`
	} `json:"definition"`
	Auth struct {
		AuthHeaderName string `json:"auth_header_name"`
	} `json:"auth"`
	UseOAuth2   bool `json:"use_oauth2"`
	VersionData struct {
		NotVersioned bool `json:"not_versioned"`
		Versions     struct {
			Default struct {
				Name string `json:"name"`
			} `json:"Default"`
		} `json:"versions"`
	} `json:"version_data"`
	Proxy struct {
		ListenPath      string `json:"listen_path"`
		TargetURL       string `json:"target_url"`
		StripListenPath bool   `json:"strip_listen_path"`
	} `json:"proxy"`
}{
	{
		Name:  "Tyk Test API",
		APIID: "b84fe1a04e5648927971c0557971565c",
		OrgID: "664a14650619d40001f1f00f",
		Definition: struct {
			Location string `json:"location"`
			Key      string `json:"key"`
		}{
			Location: "header",
			Key:      "version",
		},
		Auth: struct {
			AuthHeaderName string `json:"auth_header_name"`
		}{
			AuthHeaderName: "authorization",
		},
		UseOAuth2: true,
		VersionData: struct {
			NotVersioned bool `json:"not_versioned"`
			Versions     struct {
				Default struct {
					Name string `json:"name"`
				} `json:"Default"`
			} `json:"versions"`
		}{
			NotVersioned: true,
			Versions: struct {
				Default struct {
					Name string `json:"name"`
				} `json:"Default"`
			}{
				Default: struct {
					Name string `json:"name"`
				}{
					Name: "Default",
				},
			},
		},
		Proxy: struct {
			ListenPath      string `json:"listen_path"`
			TargetURL       string `json:"target_url"`
			StripListenPath bool   `json:"strip_listen_path"`
		}{
			ListenPath:      "/tyk-api-test/",
			TargetURL:       "https://httpbin.org",
			StripListenPath: true,
		},
	},
	// You can add more elements to the slice by following the same pattern
}
