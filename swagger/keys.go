package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/user"
)

const KeysTag = "Keys"

func Keys(r *openapi3.Reflector) error {
	return addOperations(r, getKeyWithID, updateKeyPolicy, previewKeyRequest, putKeyRequest, createKeyRequest, postKeyRequest, getListOfKeys, deleteKeyRequest, createCustomKeyRequest)
}

func getKeyWithID(r *openapi3.Reflector) error {
	// TODO::Check this query parameters
	// keyName := mux.Vars(r)["keyName"]
	// apiID := r.URL.Query().Get("api_id")
	// isHashed := r.URL.Query().Get("hashed") != ""
	// isUserName := r.URL.Query().Get("username") == "true"
	// orgID := r.URL.Query().Get("org_id")
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/keys/{keyID}")
	if err != nil {
		return err
	}
	oc.AddRespStructure(new(user.SessionState))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	oc.SetTags(KeysTag)
	oc.SetID("getKey")
	oc.SetSummary("Get a key with ID")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{keyIDParameter()}
	par = append(par, hashedQuery())
	o3.Operation().WithParameters(par...)
	oc.SetDescription("Get session info about the specified key. Should return up to date rate limit and quota usage numbers.")
	return r.AddOperation(oc)
}

func deleteKeyRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodDelete, "/tyk/keys/{keyID}")
	if err != nil {
		return err
	}
	oc.SetTags(KeysTag)
	oc.SetID("deleteKey")
	oc.AddRespStructure(new(apiModifyKeySuccess))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.SetSummary("Delete Key")
	oc.SetDescription("Deleting a key will remove it permanently from the system, however analytics relating to that key will still be available.")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{keyIDParameter(), hashedQuery()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func getListOfKeys(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/keys")
	if err != nil {
		return err
	}
	oc.AddRespStructure(new(apiAllKeys))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.SetID("listKeys")
	oc.SetDescription(" List APIs\n         Only if used without the Tyk Dashboard")
	oc.SetTags(KeysTag)
	oc.SetSummary("List Keys")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	o3.Operation().WithParameters(filterKeyQuery())
	return r.AddOperation(oc)
}

func putKeyRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPut, "/tyk/keys/{keyID}")
	if err != nil {
		return err
	}
	oc.AddReqStructure(new(user.SessionState))
	oc.SetSummary("Update Key")
	oc.SetDescription(" You can also manually add keys to Tyk using your own key-generation algorithm. It is recommended if using this approach to ensure that the OrgID being used in the API Definition and the key data is blank so that Tyk does not try to prepend or manage the key in any way.")
	oc.AddRespStructure(new(apiModifyKeySuccess))
	oc.SetID("updateKey")
	oc.SetTags(KeysTag)
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{keyIDParameter(), suppressResetQuery(), hashedQuery()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func postKeyRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/keys")
	if err != nil {
		return err
	}
	oc.SetTags(KeysTag)
	oc.SetID("addKey")
	oc.SetSummary("Create a key")
	oc.SetDescription("Tyk will generate the access token based on the OrgID specified in the API Definition and a random UUID. This ensures that keys can be \"owned\" by different API Owners should segmentation be needed at an organisational level.\n        <br/><br/>\n        API keys without access_rights data will be written to all APIs on the system (this also means that they will be created across all SessionHandlers and StorageHandlers, it is recommended to always embed access_rights data in a key to ensure that only targeted APIs and their back-ends are written to.")
	oc.AddReqStructure(new(user.SessionState))
	oc.AddRespStructure(new(apiModifyKeySuccess))
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

func createCustomKeyRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/keys/{keyID}")
	if err != nil {
		return err
	}
	oc.SetTags(KeysTag)
	oc.SetID("createCustomKey")
	oc.SetSummary("Create Custom Key / Import Key")
	// TODO::Copy the description in previous oas
	oc.SetDescription("You can use the `POST /tyk/keys/{KEY_ID}` endpoint as defined below to import existing keys into Tyk.\n\n        This example uses standard `authorization` header authentication, and assumes that the Gateway is located at `127.0.0.1:8080` and the Tyk secret is `352d20ee67be67f6340b4c0605b044b7` - update these as necessary to match your environment.\n")
	oc.AddReqStructure(new(user.SessionState))
	oc.AddRespStructure(new(apiModifyKeySuccess))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{keyIDParameter(), hashedQuery(), suppressResetQuery()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func createKeyRequest(r *openapi3.Reflector) error {
	// TODO::Inquire why we have two endpoint doing the same thing.
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/keys/create")
	if err != nil {
		return err
	}
	oc.SetTags(KeysTag)
	oc.SetID("createKey")
	oc.SetSummary("Create a key")
	oc.AddReqStructure(new(user.SessionState))
	oc.AddRespStructure(new(apiModifyKeySuccess))
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

func previewKeyRequest(r *openapi3.Reflector) error {
	// TODO::Inquire if this endpoint is public.
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/keys/preview")
	if err != nil {
		return err
	}
	oc.SetTags(KeysTag)
	oc.SetID("createAndPreviewKey")
	oc.SetSummary("Create a key and return it for preview")
	oc.SetDescription("This will create a key and return the created key that you can preview.")
	oc.AddReqStructure(new(user.SessionState))
	oc.AddRespStructure(new(user.SessionState))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	//TODO::ask why this return status 500 for wrong body
	////oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	return r.AddOperation(oc)
}

func updateKeyPolicy(r *openapi3.Reflector) error {
	// TODO::check this one as it might be wrong what is it used for
	oc, err := r.NewOperationContext(http.MethodPost, "/keys/policy/{keyID}")
	if err != nil {
		return err
	}
	oc.SetTags(KeysTag)
	oc.SetID("addPolicyToKey")
	oc.SetSummary("Add a policy to a key.")
	oc.SetDescription("This will add a Policy object to a hashed key")
	oc.AddReqStructure(new(gateway.PolicyUpdateObj))
	oc.AddRespStructure(new(apiModifyKeySuccess))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{keyIDParameter()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func keyIDParameter() openapi3.ParameterOrRef {
	desc := "The Key ID"
	return openapi3.Parameter{In: openapi3.ParameterInPath, Name: "keyID", Required: &isRequired, Description: &desc, Schema: stringSchema()}.ToParameterOrRef()
}

func hashedQuery() openapi3.ParameterOrRef {
	hasDesc := "Use the hash of the key as input instead of the full key"
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "hashed", Description: &hasDesc, Required: &isOptional, Schema: boolSchema()}.ToParameterOrRef()
}

func suppressResetQuery() openapi3.ParameterOrRef {
	// TODO::Check if this is a enum instead.
	desc := "Adding the suppress_reset parameter and setting it to 1, will cause Tyk not to reset the quota limit that is in the current live quota manager. By default Tyk will reset the quota in the live quota manager (initialising it) when adding a key. Adding the `suppress_reset` flag to the URL parameters will avoid this behaviour."
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "suppress_reset", Required: &isOptional, Description: &desc, Schema: stringSchema()}.ToParameterOrRef()
}

func filterKeyQuery() openapi3.ParameterOrRef {
	///TODO::Check if this is actually bool or is it a string with value 1
	desc := "we don't use filter for hashed keys"
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "filter", Required: &isOptional, Description: &desc, Schema: boolSchema()}.ToParameterOrRef()
}
