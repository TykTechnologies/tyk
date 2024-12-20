package swagger

import (
	"net/http"
	"time"

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
	addTag(KeysTag, KeyTagsDesc, optionalTagParameters{})
	return addOperations(r, getKeyWithID, updateKeyPolicy, previewKeyRequest, putKeyRequest, createKeyRequest, postKeyRequest, getListOfKeys, deleteKeyRequest, createCustomKeyRequest)
}

func getKeyWithID(r *openapi3.Reflector) error {
	// TODO::Check this query parameters
	// keyName := mux.Vars(r)["keyName"]
	// apiID := r.URL.Query().Get("api_id")
	// isHashed := r.URL.Query().Get("hashed") != ""
	// isUserName := r.URL.Query().Get("username") == "true"
	// orgID := r.URL.Query().Get("org_id")
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodGet,
		PathPattern: "/tyk/keys/{keyID}",
		OperationID: "getKey",
		Tag:         KeysTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	op.AddResponseWithSeparateExample(new(user.SessionState), http.StatusOK, minimalSessionState[0], func(cu *openapi.ContentUnit) {
		cu.Description = "Key fetched."
	})
	op.StatusNotFound("Key not found", func(cu *openapi.ContentUnit) {
		cu.Description = "Key not found."
	})
	op.StatusBadRequest("Key requested by hash but key hashing is not enabled.")
	oc.SetSummary("Get a key with ID.")
	//"b13d928b9972bd18"
	oc.SetDescription("Get session info about the specified key. Should return up to date rate limit and quota usage numbers.")
	op.AddQueryParameter("hashed", "Use the hash of the key as input instead of the full key.", OptionalParameterValues{
		Example: valueToInterface(true),
		Type:    openapi3.SchemaTypeBoolean,
		Enum:    []interface{}{true, false},
		Default: nil,
	})
	op.AddPathParameter("keyID", "The key ID.", OptionalParameterValues{
		Example: valueToInterface("5e9d9544a1dcd60001d0ed20e7f75f9e03534825b7aef9df749582e5"),
	})
	return op.AddOperation()
}

func deleteKeyRequest(r *openapi3.Reflector) error {
	// TODO::Check this query parameters
	// keyName := mux.Vars(r)["keyName"]
	// apiID := r.URL.Query().Get("api_id")
	// isHashed := r.URL.Query().Get("hashed") != ""
	// isUserName := r.URL.Query().Get("username") == "true"
	// orgID := r.URL.Query().Get("org_id")
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodDelete,
		PathPattern: "/tyk/keys/{keyID}",
		OperationID: "deleteKey",
		Tag:         KeysTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	op.StatusNotFound("There is no such key found", func(cu *openapi.ContentUnit) {
		cu.Description = "Key not found."
	})
	op.AddRespWithExample(apiModifyKeySuccess{
		Key:    "5e9d9544a1dcd60001d0ed20e7f75f9e03534825b7aef9df749582e5",
		Status: "ok",
		Action: "deleted",
	}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "Key deleted."
	})
	op.StatusBadRequest("Failed to remove the key")
	oc.SetSummary("Delete a key.")
	oc.SetDescription("Deleting a key will remove it permanently from the system, however analytics relating to that key will still be available.")
	op.AddQueryParameter("hashed", "Use the hash of the key as input instead of the full key.", OptionalParameterValues{
		Example: valueToInterface(false),
		Type:    openapi3.SchemaTypeBoolean,
		Enum:    []interface{}{true, false},
	})
	op.AddPathParameter("keyID", "The key ID.", OptionalParameterValues{
		Example: valueToInterface("5e9d9544a1dcd60001d0ed20e7f75f9e03534825b7aef9df749582e5"),
	})
	return op.AddOperation()
}

// Done
func getListOfKeys(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodGet,
		PathPattern: "/tyk/keys",
		OperationID: "listKeys",
		Tag:         KeysTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc

	op.AddRespWithExample(apiAllKeys{APIKeys: []string{
		"5e9d9544a1dcd60001d0ed2008500e44fa644f939b640a4b8b4ea58c",
	}}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "List of all API keys."
	})
	op.StatusNotFound("Hashed key listing is disabled in config (enable_hashed_keys_listing).", func(cu *openapi.ContentUnit) {
		cu.Description = "Disabled hashed key listing."
	})
	oc.SetDescription("List all the API keys.")
	oc.SetSummary("List keys.")
	op.AddQueryParameter("filter", "Retrieves all keys starting with the specified filter, (filter is a prefix - e.g. default* or default will return all keys starting with default  like defaultbd,defaulttwo etc). We don't use filter for hashed keys.", OptionalParameterValues{
		Example: valueToInterface("default*"),
	})
	return r.AddOperation(oc)
}

func putKeyRequest(r *openapi3.Reflector) error {
	// TODO::Check this query parameters
	// keyName := mux.Vars(r)["keyName"]
	// apiID := r.URL.Query().Get("api_id")
	// isHashed := r.URL.Query().Get("hashed") != ""
	// isUserName := r.URL.Query().Get("username") == "true"
	// orgID := r.URL.Query().Get("org_id")
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodPut,
		PathPattern: "/tyk/keys/{keyID}",
		OperationID: "updateKey",
		Tag:         KeysTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	requestBody := minimalSessionState[0]
	requestBody.Tags = append(requestBody.Tags, "update-sample-tag")
	requestBody.MetaData["new-update-key-sample"] = "update-key-sample"
	op.AddReqWithSeparateExample(user.SessionState{}, requestBody)
	oc.SetSummary("Update key.")
	oc.SetDescription(" You can also manually add keys to Tyk using your own key-generation algorithm. It is recommended that when using this approach to ensure that the OrgID being used in the API Definition and the key data is blank so that Tyk does not try to prepend or manage the key in any way.")
	op.AddRespWithExample(apiModifyKeySuccess{
		Key:    "5e9d9544a1dcd60001d0ed20766d9a6ec6b4403b93a554feefef4708",
		Status: "ok",
		Action: "modified",
	}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "Key updated."
	})
	op.StatusBadRequest("Request malformed")
	op.StatusNotFound("Key is not found", func(cu *openapi.ContentUnit) {
		cu.Description = "Key not found."
	})
	op.StatusInternalServerError("Failed to create key, ensure security settings are correct.")

	op.AddQueryParameter("suppress_reset", "Adding the suppress_reset parameter and setting it to 1 will cause Tyk not to reset the quota limit that is in the current live quota manager. By default Tyk will reset the quota in the live quota manager (initialising it) when adding a key. Adding the `suppress_reset` flag to the URL parameters will avoid this behaviour.", OptionalParameterValues{
		Example: valueToInterface("1"),

		Enum: []interface{}{"1"},
	})
	op.AddQueryParameter("hashed", "When set to true the key_hash returned will be similar to the un-hashed key name.", OptionalParameterValues{
		Example: valueToInterface(true),
		Type:    openapi3.SchemaTypeBoolean,
		Enum:    []interface{}{true, false},
	})
	op.AddPathParameter("keyID", "ID of the key you want to update.", OptionalParameterValues{
		Example: valueToInterface("5e9d9544a1dcd60001d0ed20766d9a6ec6b4403b93a554feefef4708"),
	})
	return op.AddOperation()
}

func postKeyRequest(r *openapi3.Reflector) error {
	// TODO::to check if hashed query is part of this request
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodPost,
		PathPattern: "/tyk/keys",
		OperationID: "addKey",
		Tag:         KeysTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	oc.SetSummary("Create a key.")
	oc.SetDescription("Tyk will generate the access token based on the OrgID specified in the API Definition and a random UUID. This ensures that keys can be owned by different API Owners should segmentation be needed at an organisational level.\n <br/><br/>\n  API keys without access_rights data will be written to all APIs on the system (this also means that they will be created across all SessionHandlers and StorageHandlers, it is recommended to always embed access_rights data in a key to ensure that only targeted APIs and their back-ends are written to.")
	op.AddReqWithSeparateExample(new(user.SessionState), minimalSessionState[0])

	op.AddRespWithExample(apiModifyKeySuccess{
		Key:    "5e9d9544a1dcd60001d0ed20a2290376f89846b798b7e5197584ef6d",
		Status: "ok",
		Action: "added",
	}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "New key added."
	})
	op.StatusInternalServerError("Failed to create key, ensure security settings are correct.")
	op.StatusBadRequest("Request malformed")

	op.AddQueryParameter("hashed", "When set to true the key_hash returned will be similar to the un-hashed key name.", OptionalParameterValues{
		Example: valueToInterface(true),
		Type:    openapi3.SchemaTypeBoolean,
		Enum:    []interface{}{true, false},
	})

	return op.AddOperation()
}

func createCustomKeyRequest(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodPost,
		PathPattern: "/tyk/keys/{keyID}",
		OperationID: "createCustomKey",
		Tag:         KeysTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	oc.SetSummary("Create custom key / Import key")
	// TODO::Copy the description in previous oas
	// TODO::check if suppress reset is required.
	oc.SetDescription("You can use this endpoint to import existing keys into Tyk or to create a new custom key.")
	op.AddReqWithSeparateExample(new(user.SessionState), minimalSessionState[0])
	op.AddRespWithExample(apiModifyKeySuccess{
		Key:    "5e9d9544a1dcd60001d0ed20customKey",
		Status: "ok",
		Action: "added",
	}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "New custom key added."
	})
	op.StatusBadRequest("Request malformed")
	op.StatusInternalServerError("Failed to create key, ensure security settings are correct.")
	op.AddQueryParameter("suppress_reset", "Adding the suppress_reset parameter and setting it to 1, will cause Tyk not to reset the quota limit that is in the current live quota manager. By default Tyk will reset the quota in the live quota manager (initialising it) when adding a key. Adding the `suppress_reset` flag to the URL parameters will avoid this behaviour.", OptionalParameterValues{
		Example: valueToInterface("1"),

		Enum: []interface{}{"1"},
	})
	op.AddQueryParameter("hashed", "When set to true the key_hash returned will be similar to the un-hashed key name.", OptionalParameterValues{
		Example: valueToInterface(true),
		Type:    openapi3.SchemaTypeBoolean,
		Enum:    []interface{}{true, false},
	})
	op.AddPathParameter("keyID", "Name to give the custom key.", OptionalParameterValues{
		Example: valueToInterface("customKey"),
	})

	return op.AddOperation()
}

func createKeyRequest(r *openapi3.Reflector) error {
	// TODO::Inquire why we have two endpoint doing the same thing.
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodPost,
		PathPattern: "/tyk/keys/create",
		OperationID: "createKey",
		Tag:         KeysTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	oc.SetSummary("Create a key.")
	oc.SetDescription("Create a key.")
	op.AddReqWithSeparateExample(new(user.SessionState), minimalSessionState[0])
	op.AddRespWithExample(apiModifyKeySuccess{
		Key:    "5e9d9544a1dcd60001d0ed207eb558517c3c48fb826c62cc6f6161eb",
		Status: "ok",
		Action: "added",
	}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "Key created."
	})
	op.AddGenericErrorResponse(http.StatusInternalServerError, "Unmarshalling failed", func(cu *openapi.ContentUnit) {
		cu.Description = "Malformed body."
	})
	op.StatusBadRequest("Failed to create key, keys must have at least one Access Rights record set.", func(cu *openapi.ContentUnit) {
		cu.Description = "No access right."
	})
	return op.AddOperation()
}

func previewKeyRequest(r *openapi3.Reflector) error {
	// TODO::in the code we do not check for applyPolicies errors
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodPost,
		PathPattern: "/tyk/keys/preview",
		OperationID: "validateAKeyDefinition",
		Tag:         KeysTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	oc.SetSummary("This will validate a key definition.")
	oc.SetDescription("This will check if the body of a key definition is valid. And return a response with how the key would look like if you were to create it.")
	op.AddReqWithSeparateExample(user.SessionState{}, minimalSessionState[0])
	op.AddResponseWithSeparateExample(user.SessionState{}, http.StatusOK, minimalSessionState[0], func(cu *openapi.ContentUnit) {
		cu.Description = "Key definition is valid."
	})
	op.StatusInternalServerError("Unmarshalling failed")
	return op.AddOperation()
}

// Done
func updateKeyPolicy(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodPost,
		PathPattern: "/tyk/keys/policy/{keyID}",
		OperationID: "setPoliciesToHashedKey",
		Tag:         KeysTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	oc.SetSummary("Set policies for a hashed key.")
	oc.SetDescription("This will set policies to a hashed key.")
	op.AddReqWithExample(gateway.PolicyUpdateObj{
		ApplyPolicies: []string{"5ead7120575961000181867e"},
	})
	op.AddRespWithExample(apiModifyKeySuccess{
		Key:    "5e9d9544a1dcd60001d0ed207eb558517c3c48fb826c62cc6f6161eb",
		Status: "ok",
		Action: "updated",
	}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "Updated hashed key."
	})
	op.StatusBadRequest("Couldn't decode instruction", func(cu *openapi.ContentUnit) {
		cu.Description = "Malformed request body."
	})
	op.StatusNotFound("Key not found", func(cu *openapi.ContentUnit) {
		cu.Description = "Key not found."
	})
	op.StatusInternalServerError("Could not write key data.")
	op.AddPathParameter("keyID", "Name to give the custom key.", OptionalParameterValues{
		Example: valueToInterface("5e9d9544a1dcd60001d0ed207eb558517c3c48fb826c62cc6f6161eb"),
	})
	return op.AddOperation()
}

var minimalSessionState = []struct {
	Allowance          int       `json:"allowance"`
	Rate               int       `json:"rate"`
	Per                int       `json:"per"`
	ThrottleInterval   int       `json:"throttle_interval"`
	ThrottleRetryLimit int       `json:"throttle_retry_limit"`
	DateCreated        time.Time `json:"date_created"`
	QuotaMax           int       `json:"quota_max"`
	QuotaRenews        int64     `json:"quota_renews"`
	QuotaRenewalRate   int       `json:"quota_renewal_rate"`
	AccessRights       map[string]struct {
		APIName     string   `json:"api_name"`
		APIID       string   `json:"api_id"`
		Versions    []string `json:"versions"`
		AllowedURLs []struct {
			URL     string   `json:"url"`
			Methods []string `json:"methods"`
		} `json:"allowed_urls"`
		Limit struct {
			Rate               int `json:"rate"`
			Per                int `json:"per"`
			ThrottleInterval   int `json:"throttle_interval"`
			ThrottleRetryLimit int `json:"throttle_retry_limit"`
			QuotaMax           int `json:"quota_max"`
			QuotaRemaining     int `json:"quota_remaining"`
			QuotaRenewalRate   int `json:"quota_renewal_rate"`
		} `json:"limit"`
	} `json:"access_rights"`
	OrgID                   string                 `json:"org_id"`
	ApplyPolicies           []string               `json:"apply_policies"`
	EnableDetailedRecording bool                   `json:"enable_detailed_recording"`
	MetaData                map[string]interface{} `json:"meta_data"`
	Tags                    []string               `json:"tags"`
	Alias                   string                 `json:"alias"`
	LastUpdated             string                 `json:"last_updated"`
}{
	{
		Allowance:          1000,
		Rate:               1000,
		Per:                60,
		ThrottleInterval:   10,
		ThrottleRetryLimit: 10,
		DateCreated:        time.Date(2024, 8, 9, 14, 40, 34, 876140000, time.FixedZone("EEST", 3*60*60)),
		QuotaMax:           10000,
		QuotaRenews:        1723207234,
		QuotaRenewalRate:   3600,
		AccessRights: map[string]struct {
			APIName     string   `json:"api_name"`
			APIID       string   `json:"api_id"`
			Versions    []string `json:"versions"`
			AllowedURLs []struct {
				URL     string   `json:"url"`
				Methods []string `json:"methods"`
			} `json:"allowed_urls"`
			Limit struct {
				Rate               int `json:"rate"`
				Per                int `json:"per"`
				ThrottleInterval   int `json:"throttle_interval"`
				ThrottleRetryLimit int `json:"throttle_retry_limit"`
				QuotaMax           int `json:"quota_max"`
				QuotaRemaining     int `json:"quota_remaining"`
				QuotaRenewalRate   int `json:"quota_renewal_rate"`
			} `json:"limit"`
		}{
			"itachi-api": {
				APIName:  "Itachi api",
				APIID:    "8ddd91f3cda9453442c477b06c4e2da4",
				Versions: []string{"Default"},
				AllowedURLs: []struct {
					URL     string   `json:"url"`
					Methods []string `json:"methods"`
				}{
					{
						URL:     "/users",
						Methods: []string{"GET"},
					},
				},
				Limit: struct {
					Rate               int `json:"rate"`
					Per                int `json:"per"`
					ThrottleInterval   int `json:"throttle_interval"`
					ThrottleRetryLimit int `json:"throttle_retry_limit"`
					QuotaMax           int `json:"quota_max"`
					QuotaRemaining     int `json:"quota_remaining"`
					QuotaRenewalRate   int `json:"quota_renewal_rate"`
				}{
					Rate:               1000,
					Per:                60,
					ThrottleInterval:   10,
					ThrottleRetryLimit: 10,
					QuotaMax:           10000,
					QuotaRemaining:     10000,
					QuotaRenewalRate:   3600,
				},
			},
		},
		OrgID:                   "5e9d9544a1dcd60001d0ed20",
		ApplyPolicies:           []string{"5ead7120575961000181867e"},
		EnableDetailedRecording: true,
		MetaData: map[string]interface{}{
			"tyk_developer_id": "62b3fb9a1d5e4f00017226f5",
			"update":           "sample policy update",
			"user_type":        "mobile_user",
		},
		Tags:        []string{"security", "edge", "edge-eu"},
		Alias:       "portal-key",
		LastUpdated: "1723203634",
	},
}
