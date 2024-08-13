package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/user"
)

const (
	OrgTag     = "Organisation Quotas"
	OrgTagDesc = `It is possible to force API quota and rate limit across all keys that belong to a specific organisation ID. Rate limiting at an organisation level is useful for creating tiered access levels and trial accounts.<br />

The Organisation rate limiting middleware works with both Quotas and Rate Limiters. In order to manage this functionality, a simple API has been put in place to manage these sessions. <br />

Although the Organisation session-limiter uses the same session object, all other security keys are optional as they are not used. <br />

<h3>Managing active status</h3> <br />

To disallow access to an entire group of keys without rate limiting the organisation, create a session object with the "is_inactive" key set to true. This will block access before any other middleware is executed. It is useful when managing subscriptions for an organisation group and access needs to be blocked because of non-payment. <br />
`
)

func OrgsApi(r *openapi3.Reflector) error {
	addTag(OrgTag, OrgTagDesc, optionalTagParameters{})
	return addOperations(r, getSingleOrgKeyWithID, deleteOrgKeyRequest, createOrgKey, UpdateOrgKey, getOrgKeys)
}

// done
func getOrgKeys(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodGet,
		PathPattern: "/tyk/org/keys",
		OperationID: "listOrgKeys",
		Tag:         OrgTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	op.StatusNotFound("ORG not found", func(cu *openapi.ContentUnit) {
		cu.Description = "ORG not found"
	})
	op.AddRespWithExample(apiAllKeys{APIKeys: []string{
		"5e9d9544a1dcd60001d0ed2008500e44fa644f939b640a4b8b4ea58c",
	}}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "List of all org keys"
	})
	oc.SetSummary("List Organisation Keys")
	oc.SetDescription("You can now set rate limits at the organisation level by using the following fields - allowance and rate. These are the number of allowed requests for the specified per value, and need to be set to the same value. If you don't want to have organisation level rate limiting, set 'rate' or 'per' to zero, or don't add them to your request.")
	op.AddQueryParameter("filter", "Retrieves all keys starting with the specified filter(filter is a prefix - e.g. default* or default will return all keys starting with default  like defaultbd,defaulttwo etc).We don't use filter for hashed keys", OptionalParameterValues{
		Example: valueToInterface("default*"),
	})
	return op.AddOperation()
}

func getSingleOrgKeyWithID(r *openapi3.Reflector) error {
	// TODO::Check this query parameters
	// keyName := mux.Vars(r)["keyName"]
	// apiID := r.URL.Query().Get("api_id")
	// isHashed := r.URL.Query().Get("hashed") != ""
	// isUserName := r.URL.Query().Get("username") == "true"
	// orgID := r.URL.Query().Get("org_id")

	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodGet,
		PathPattern: "/tyk/org/keys/{keyID}",
		OperationID: "getOrgKey",
		Tag:         OrgTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	op.StatusNotFound("Org not found", func(cu *openapi.ContentUnit) {
		cu.Description = "Org not found"
	})
	op.AddRespWithExample(minimalSessionState[0], http.StatusOK, func(cu *openapi.ContentUnit) {
	})
	oc.SetSummary("Get an Organisation Key")
	oc.SetDescription("Get session info about specified organisation key. Should return up to date rate limit and quota usage numbers.")
	op.AddQueryParameter("orgID", "The Org ID", OptionalParameterValues{
		Example: valueToInterface("664a14650619d40001f1f00f"),
	})
	op.AddPathParameter("keyID", "The Key ID", OptionalParameterValues{
		Example: valueToInterface("e389ae00a2b145feaf28d6cc11f0f86d"),
	})
	return op.AddOperation()
}

func deleteOrgKeyRequest(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodDelete,
		PathPattern: "/tyk/org/keys/{keyID}",
		OperationID: "deleteOrgKey",
		Tag:         OrgTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	op.StatusNotFound("Org not found", func(cu *openapi.ContentUnit) {
		cu.Description = "Org not found"
	})
	op.StatusBadRequest("Failed to remove the key")
	oc.AddRespStructure(new(apiModifyKeySuccess))
	oc.SetSummary("Delete Key")
	oc.SetDescription("Deleting a key will remove all limits from organisation. It does not affects regular keys created within organisation.")
	op.AddRespWithExample(apiModifyKeySuccess{
		Key:    "e389ae00a2b145feaf28d6cc11f0f86d",
		Status: "ok",
		Action: "deleted",
	}, http.StatusOK, func(cu *openapi.ContentUnit) {
	})
	///TODO::check what keyid really is if it is actually orgID
	op.AddPathParameter("keyID", "The Key ID", OptionalParameterValues{
		Example: valueToInterface("e389ae00a2b145feaf28d6cc11f0f86d"),
	})
	return op.AddOperation()
}

func createOrgKey(r *openapi3.Reflector) error {
	///TODO::check query parameter reset_quota in the code
	///TODO::check if path should be org_Id or key id
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodPost,
		PathPattern: "/tyk/org/keys/{keyID}",
		OperationID: "addOrgKey",
		Tag:         OrgTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	oc.SetSummary("Create an organisation key")
	oc.SetDescription("This work similar to Keys API except that Key ID is always equals Organisation ID")
	op.AddReqWithSeparateExample(new(user.SessionState), minimalSessionState[0])
	op.StatusBadRequest("Request malformed")
	op.StatusNotFound("No such organisation found in Active API list")
	op.StatusInternalServerError("Error writing to key store ")
	///TODO::check what keyid really is if it is actually orgID
	op.AddPathParameter("keyID", "The Key ID", OptionalParameterValues{
		Example: valueToInterface("e389ae00a2b145feaf28d6cc11f0f86d"),
	})
	op.AddRespWithExample(apiModifyKeySuccess{
		Key:    "e389ae00a2b145feaf28d6cc11f0f86d",
		Status: "ok",
		Action: "added",
	}, http.StatusOK)
	op.AddQueryParameter("reset_quota", "Adding the reset_quota parameter and setting it to 1, will cause Tyk reset the organisations quota in the live quota manager, it is recommended to use this mechanism to reset organisation-level access if a monthly subscription is in place.", OptionalParameterValues{
		Example: valueToInterface("1"),
		Enum:    []interface{}{"1"},
	})
	return op.AddOperation()
}

func UpdateOrgKey(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodPut,
		PathPattern: "/tyk/org/keys/{keyID}",
		OperationID: "updateOrgKey",
		Tag:         OrgTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	requestBody := minimalSessionState[0]
	requestBody.Tags = append(requestBody.Tags, "update-sample-tag")
	requestBody.MetaData["new-update-key-sample"] = "update-key-sample"
	op.AddReqWithSeparateExample(user.SessionState{}, requestBody)
	oc.SetSummary("Update Organisation Key")
	oc.SetDescription("This work similar to Keys API except that Key ID is always equals Organisation ID\n\nFor Gateway v2.6.0 onwards, you can now set rate limits at the organisation level by using the following fields - allowance and rate. These are the number of allowed requests for the specified per value, and need to be set to the same value. If you don't want to have organisation level rate limiting, set `rate` or `per` to zero, or don't add them to your request.")
	oc.AddRespStructure(new(apiModifyKeySuccess))
	op.StatusBadRequest("Request malformed")
	op.StatusNotFound("No such organisation found in Active API list")
	op.StatusInternalServerError("Error writing to key store ")
	// TODO::Check about reset quota if it is allowed here
	op.AddQueryParameter("reset_quota", "Adding the reset_quota parameter and setting it to 1, will cause Tyk reset the organisations quota in the live quota manager, it is recommended to use this mechanism to reset organisation-level access if a monthly subscription is in place.", OptionalParameterValues{
		Example: valueToInterface("1"),
		Enum:    []interface{}{"1"},
	})
	op.AddPathParameter("keyID", "The Key ID", OptionalParameterValues{
		Example: valueToInterface("e389ae00a2b145feaf28d6cc11f0f86d"),
	})
	return op.AddOperation()
}
