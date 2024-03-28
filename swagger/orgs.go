package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/user"
)

const OrgTag = "Organisation Quotas"

func OrgsApi(r *openapi3.Reflector) error {
	return addOperations(r, getSingleOrgKeyWithID, deleteOrgKeyRequest, createOrgKey, UpdateOrgKey, getOrgKeys)
}

func getOrgKeys(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/org/keys")
	if err != nil {
		return err
	}
	oc.AddRespStructure(new(apiAllKeys))
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	oc.SetID("listOrgKeys")
	oc.SetSummary("List Organisation Keys")
	oc.SetTags(OrgTag)
	oc.SetDescription("You can now set rate limits at the organisation level by using the following fields - allowance and rate. These are the number of allowed requests for the specified per value, and need to be set to the same value. If you don't want to have organisation level rate limiting, set 'rate' or 'per' to zero, or don't add them to your request.")
	o3.Operation().WithParameters(filterKeyQuery())
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	return r.AddOperation(oc)
}

func getSingleOrgKeyWithID(r *openapi3.Reflector) error {
	// TODO::Check this query parameters
	// keyName := mux.Vars(r)["keyName"]
	// apiID := r.URL.Query().Get("api_id")
	// isHashed := r.URL.Query().Get("hashed") != ""
	// isUserName := r.URL.Query().Get("username") == "true"
	// orgID := r.URL.Query().Get("org_id")
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/org/keys/{keyID}")
	if err != nil {
		return err
	}
	oc.AddRespStructure(new(user.SessionState))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.SetTags(OrgTag)
	oc.SetID("getOrgKey")
	oc.SetSummary("Get an Organisation Key")
	oc.SetDescription("Get session info about specified organisation key. Should return up to date rate limit and quota usage numbers.")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{keyIDParameter()}
	///par = append(par, getKeyQuery()...)
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func deleteOrgKeyRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodDelete, "/tyk/org/keys/{keyID}")
	if err != nil {
		return err
	}
	oc.SetTags(OrgTag)
	oc.SetID("deleteOrgKey")
	oc.AddRespStructure(new(apiModifyKeySuccess))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.SetSummary("Delete Key")
	oc.SetDescription("Deleting a key will remove all limits from organisation. It does not affects regular keys created within organisation.")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{keyIDParameter()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func createOrgKey(r *openapi3.Reflector) error {
	///TODO::check query parameter reset_quota in the code
	///TODO::check if path should be org_Id or key id
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/org/keys/{keyID}")
	if err != nil {
		return err
	}
	oc.SetTags(OrgTag)
	oc.SetID("addOrgKey")
	oc.SetSummary("Create an organisation key")
	oc.SetDescription("This work similar to Keys API except that Key ID is always equals Organisation ID")
	oc.AddReqStructure(new(user.SessionState))
	oc.AddRespStructure(new(apiModifyKeySuccess))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{keyIDParameter(), resetQuotaKeyQuery()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func UpdateOrgKey(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPut, "/tyk/org/keys/{keyID}")
	if err != nil {
		return err
	}
	oc.AddReqStructure(new(user.SessionState))
	oc.SetSummary("Update Organisation Key")
	oc.SetDescription("This work similar to Keys API except that Key ID is always equals Organisation ID\n\nFor Gateway v2.6.0 onwards, you can now set rate limits at the organisation level by using the following fields - allowance and rate. These are the number of allowed requests for the specified per value, and need to be set to the same value. If you don't want to have organisation level rate limiting, set `rate` or `per` to zero, or don't add them to your request.")
	oc.AddRespStructure(new(apiModifyKeySuccess))
	oc.SetID("updateOrgKey")
	oc.SetTags(OrgTag)
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	// TODO::Check about reset quota if it is allowed here
	par := []openapi3.ParameterOrRef{keyIDParameter(), resetQuotaKeyQuery()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func resetQuotaKeyQuery() openapi3.ParameterOrRef {
	isRequired := false
	///TODO::check query parameter reset_quota in the code and make sure it is accurate also check the description
	///TODO:: should change this to enum
	desc := "Adding the reset_quota parameter and setting it to 1, will cause Tyk reset the organisations quota in the live quota manager, it is recommended to use this mechanism to reset organisation-level access if a monthly subscription is in place."
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "reset_quota", Required: &isRequired, Description: &desc, Schema: resetQuotaSchema()}.ToParameterOrRef()
}
