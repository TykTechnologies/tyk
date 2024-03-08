package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/user"
)

func Keys(r *openapi3.Reflector) error {
	err := putKeyRequest(r)
	if err != nil {
		return err
	}
	err = createKeyRequest(r)
	if err != nil {
		return err
	}
	err = postKeyRequest(r)
	if err != nil {
		return err
	}
	return getKeyWithID(r)
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
	oc.AddReqStructure(new(user.SessionState))
	oc.AddRespStructure(new(user.SessionState))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	oc.SetTags("Keys")
	oc.SetID("getKey")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{keyIDParameter()}
	par = append(par, getKeyQuery()...)
	o3.Operation().WithParameters(par...)
	oc.SetDescription("Get session info about the specified key. Should return up to date rate limit and quota usage numbers.")
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
	oc.SetTags("Keys")
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{keyIDParameter()}
	par = append(par, updateKeyQuery())
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func postKeyRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/keys/create")
	if err != nil {
		return err
	}
	oc.SetTags("Keys")
	oc.SetID("addKey")
	oc.SetSummary("Create a key")
	oc.SetDescription(" Tyk will generate the access token based on the OrgID specified in the API Definition and a random UUID. This ensures that keys can be \"owned\" by different API Owners should segmentation be needed at an organisational level.\n        <br/><br/>\n        API keys without access_rights data will be written to all APIs on the system (this also means that they will be created across all SessionHandlers and StorageHandlers, it is recommended to always embed access_rights data in a key to ensure that only targeted APIs and their back-ends are written to.")
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

func createKeyRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/keys/create")
	if err != nil {
		return err
	}
	oc.SetTags("Keys")
	oc.SetID("createKey")
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

func keyIDParameter() openapi3.ParameterOrRef {
	isRequired := true
	desc := "The Key ID"
	return openapi3.Parameter{In: openapi3.ParameterInPath, Name: "keyID", Required: &isRequired, Description: &desc}.ToParameterOrRef()
}

func getKeyQuery() []openapi3.ParameterOrRef {
	hasDesc := "Use the hash of the key as input instead of the full key"
	isRequired := false
	///example:=false
	return []openapi3.ParameterOrRef{
		openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "hashed", Description: &hasDesc, Required: &isRequired}.ToParameterOrRef(),
	}
}

func updateKeyQuery() openapi3.ParameterOrRef {
	isRequired := false
	desc := "Adding the suppress_reset parameter and setting it to 1, will cause Tyk not to reset the quota limit that is in the current live quota manager. By default Tyk will reset the quota in the live quota manager (initialising it) when adding a key. Adding the `suppress_reset` flag to the URL parameters will avoid this behaviour."
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "suppress_reset", Required: &isRequired, Description: &desc}.ToParameterOrRef()
}
