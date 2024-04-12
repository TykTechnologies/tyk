package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/user"
)

const (
	KeysTag     = "Keys"
	KeyTagsDesc = `All keys that are used to access services via Tyk correspond to a session object that informs Tyk about the context of this particular token, like access rules and rate/quota allowance.
`
)

func Keys(r *openapi3.Reflector) error {
	addTag(KeysTag, KeyTagsDesc)
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
	oc.AddRespStructure(new(user.SessionState), func(cu *openapi.ContentUnit) {
		cu.Description = "Key fetched"
	})
	statusNotFound(oc, "Key not found")
	forbidden(oc)
	statusBadRequest(oc, "requesting key using a hash when key hashing is not enabled")
	oc.SetTags(KeysTag)
	oc.SetID("getKey")
	oc.SetSummary("Get a key with ID")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	//"b13d928b9972bd18"
	par := []openapi3.ParameterOrRef{keyIDParameter()}
	par = append(par, hashedQuery())
	o3.Operation().WithParameters(par...)
	oc.SetDescription("Get session info about the specified key. Should return up to date rate limit and quota usage numbers.")
	return r.AddOperation(oc)
}

func deleteKeyRequest(r *openapi3.Reflector) error {
	// TODO::Check this query parameters
	// keyName := mux.Vars(r)["keyName"]
	// apiID := r.URL.Query().Get("api_id")
	// isHashed := r.URL.Query().Get("hashed") != ""
	// isUserName := r.URL.Query().Get("username") == "true"
	// orgID := r.URL.Query().Get("org_id")
	oc, err := r.NewOperationContext(http.MethodDelete, "/tyk/keys/{keyID}")
	if err != nil {
		return err
	}
	oc.SetTags(KeysTag)
	oc.SetID("deleteKey")
	oc.AddRespStructure(new(apiModifyKeySuccess), func(cu *openapi.ContentUnit) {
		cu.Description = "Key deleted"
	})
	statusBadRequest(oc, "Failed to remove the key")
	statusNotFound(oc, "Key not found")
	forbidden(oc)
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

// Done
func getListOfKeys(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/keys")
	if err != nil {
		return err
	}
	oc.AddRespStructure(new(apiAllKeys), func(cu *openapi.ContentUnit) {
		cu.Description = "List of all API keys"
	})
	forbidden(oc)
	statusNotFound(oc, "When hash_keys is enabled in gateway config and enable_hashed_keys_listing is disabled")
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
	// TODO::Check this query parameters
	// keyName := mux.Vars(r)["keyName"]
	// apiID := r.URL.Query().Get("api_id")
	// isHashed := r.URL.Query().Get("hashed") != ""
	// isUserName := r.URL.Query().Get("username") == "true"
	// orgID := r.URL.Query().Get("org_id")
	oc, err := r.NewOperationContext(http.MethodPut, "/tyk/keys/{keyID}")
	if err != nil {
		return err
	}
	oc.AddReqStructure(new(user.SessionState))
	oc.SetSummary("Update Key")
	oc.SetDescription(" You can also manually add keys to Tyk using your own key-generation algorithm. It is recommended if using this approach to ensure that the OrgID being used in the API Definition and the key data is blank so that Tyk does not try to prepend or manage the key in any way.")
	oc.AddRespStructure(new(apiModifyKeySuccess), func(cu *openapi.ContentUnit) {
		cu.Description = "Key updated"
	})
	oc.SetID("updateKey")
	oc.SetTags(KeysTag)
	statusBadRequest(oc, "Malformed request")
	statusNotFound(oc, "Key not found")
	statusInternalServerError(oc, "Unexpected error")
	forbidden(oc)
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{keyIDParameter(), suppressResetQuery(), hashedQuery()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func postKeyRequest(r *openapi3.Reflector) error {
	// TODO::to check if hashed query is part of this request
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/keys")
	if err != nil {
		return err
	}
	oc.SetTags(KeysTag)
	oc.SetID("addKey")
	oc.SetSummary("Create a key")
	oc.SetDescription("Tyk will generate the access token based on the OrgID specified in the API Definition and a random UUID. This ensures that keys can be \"owned\" by different API Owners should segmentation be needed at an organisational level.\n        <br/><br/>\n        API keys without access_rights data will be written to all APIs on the system (this also means that they will be created across all SessionHandlers and StorageHandlers, it is recommended to always embed access_rights data in a key to ensure that only targeted APIs and their back-ends are written to.")
	oc.AddReqStructure(new(user.SessionState))
	oc.AddRespStructure(new(apiModifyKeySuccess), func(cu *openapi.ContentUnit) {
		cu.Description = "New Key added"
	})
	statusInternalServerError(oc, "Unexpected error")
	forbidden(oc)
	statusBadRequest(oc, "Malformed request")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}

	o3.Operation().WithParameters(hashedQuery("when set to true the key_hash returned will be similar to the un hashed key name"))
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
	// TODO::check if suppress reset is required.
	oc.SetDescription("You can use the `POST /tyk/keys/{KEY_ID}` endpoint as defined below to import existing keys into Tyk.\n\n        This example uses standard `authorization` header authentication, and assumes that the Gateway is located at `127.0.0.1:8080` and the Tyk secret is `352d20ee67be67f6340b4c0605b044b7` - update these as necessary to match your environment.\n")
	oc.AddReqStructure(new(user.SessionState))
	oc.AddRespStructure(new(apiModifyKeySuccess), func(cu *openapi.ContentUnit) {
		cu.Description = "New custom Key added"
	})
	statusInternalServerError(oc, "Unexpected error")
	forbidden(oc)
	statusBadRequest(oc, "Malformed request")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{keyIDParameter(), suppressResetQuery(), hashedQuery("when set to true the key_hash returned will be similar to the un hashed key name")}
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
	oc.AddRespStructure(new(apiModifyKeySuccess), func(cu *openapi.ContentUnit) {
		cu.Description = "Key created"
	})
	statusBadRequest(oc, "keys must have at least one Access Rights record set")
	statusInternalServerError(oc, "Failed to create key")
	forbidden(oc)
	return r.AddOperation(oc)
}

func previewKeyRequest(r *openapi3.Reflector) error {
	// TODO::in the code we do not check for applyPolicies errors
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/keys/preview")
	if err != nil {
		return err
	}
	oc.SetTags(KeysTag)
	oc.SetID("validateAKeyDefinition")
	oc.SetSummary("This will validate key a definition")
	oc.SetDescription("This will check if the body of a key definition is valid.And return a response with how the key would look like if you create it")
	oc.AddReqStructure(new(user.SessionState))
	oc.AddRespStructure(new(user.SessionState), func(cu *openapi.ContentUnit) {
		cu.Description = "Key definition is valid"
	})
	statusInternalServerError(oc, "malformed request body")
	forbidden(oc)
	// TODO::ask why this return status 500 for wrong body
	return r.AddOperation(oc)
}

// Done
func updateKeyPolicy(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/keys/policy/{keyID}")
	if err != nil {
		return err
	}
	oc.SetTags(KeysTag)
	oc.SetID("setPoliciesToHashedKey")
	oc.SetSummary("Set policies for a hashed key.")
	oc.SetDescription("This will set policies  to a hashed key")
	oc.AddReqStructure(new(gateway.PolicyUpdateObj))
	oc.AddRespStructure(new(apiModifyKeySuccess), func(cu *openapi.ContentUnit) {
		cu.Description = "Updated hashed key"
	})
	statusBadRequest(oc, "malformed request body")
	forbidden(oc)
	statusNotFound(oc, "Key not found")
	statusInternalServerError(oc, "Unexpected error")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{keyIDParameter()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func keyIDParameter() openapi3.ParameterOrRef {
	///b13d928b9972bd18
	desc := "The Key ID"
	return openapi3.Parameter{In: openapi3.ParameterInPath, Name: "keyID", Required: &isRequired, Description: &desc, Schema: stringSchema()}.ToParameterOrRef()
}

func hashedQuery(description ...string) openapi3.ParameterOrRef {
	desc := "Use the hash of the key as input instead of the full key"
	if len(description) != 0 {
		desc = description[0]
	}
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "hashed", Description: stringPointerValue(desc), Required: &isOptional, Schema: boolSchema()}.ToParameterOrRef()
}

func suppressResetQuery() openapi3.ParameterOrRef {
	// TODO::Check if this is a enum instead.
	desc := "Adding the suppress_reset parameter and setting it to 1, will cause Tyk not to reset the quota limit that is in the current live quota manager. By default Tyk will reset the quota in the live quota manager (initialising it) when adding a key. Adding the `suppress_reset` flag to the URL parameters will avoid this behaviour."
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "suppress_reset", Required: &isOptional, Description: &desc, Schema: stringEnumSchema("1")}.ToParameterOrRef()
}

func filterKeyQuery() openapi3.ParameterOrRef {
	var example interface{} = "default*"
	desc := "Retrieves all keys starting with the specified filter(filter is a prefix - e.g. default* or default will return all keys starting with default  like defaultbd,defaulttwo etc).We don't use filter for hashed keys"
	return openapi3.Parameter{Example: &example, In: openapi3.ParameterInQuery, Name: "filter", Required: &isOptional, Description: &desc, Schema: stringSchema()}.ToParameterOrRef()
}
