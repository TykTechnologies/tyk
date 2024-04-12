package swagger

import (
	"net/http"

	"github.com/swaggest/jsonschema-go"
	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/gateway"
)

const OAuthTag = "OAuth"

func OAuthApi(r *openapi3.Reflector) error {
	return addOperations(r, rotateOauthClientHandler, invalidateOauthRefresh,
		updateOauthClient, getApisForOauthApp, purgeLapsedOAuthTokens, listOAuthClients,
		deleteOAuthClient, getSingleOAuthClient, getAuthClientTokens, revokeTokenHandler,
		createOauthClient, revokeAllTokensHandler,
	)
}

// Done
func createOauthClient(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/oauth/clients/create")
	if err != nil {
		return err
	}
	oc.SetTags(OAuthTag)
	oc.AddReqStructure(new(gateway.NewClientRequest))
	oc.AddRespStructure(new(gateway.NewClientRequest), func(cu *openapi.ContentUnit) {
		cu.Description = "Client created"
	})
	forbidden(oc)
	statusInternalServerError(oc, "Internal server error")
	// TODO::ask why we return 500 instead of 400 for wrong body
	statusBadRequest(oc, "Bad request")
	oc.SetID("createOAuthClient")
	oc.SetSummary("Create new OAuth client")
	oc.SetDescription("Any OAuth keys must be generated with the help of a client ID. These need to be pre-registered with Tyk before they can be used (in a similar vein to how you would register your app with Twitter before attempting to ask user permissions using their API).\n        <br/><br/>\n        <h3>Creating OAuth clients with Access to Multiple APIs</h3>\n        New from Tyk Gateway 2.6.0 is the ability to create OAuth clients with access to more than one API. If you provide the api_id it works the same as in previous releases. If you don't provide the api_id the request uses policy access rights and enumerates APIs from their setting in the newly created OAuth-client.\n")
	return r.AddOperation(oc)
}

// Done
func rotateOauthClientHandler(r *openapi3.Reflector) error {
	// TODO::find summary and description for this
	// TODO::this is not in  the old swagger
	oc, err := r.NewOperationContext(http.MethodPut, "/tyk/oauth/clients/{apiID}/{keyName}/rotate")
	if err != nil {
		return err
	}
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	statusNotFound(oc, "Returned when api with the api_id sent in the apiID parameter  doesn't exist or when the OAuth Client ID is not found")
	statusInternalServerError(oc, "internal server error")
	oc.AddRespStructure(new(gateway.NewClientRequest), openapi.WithHTTPStatus(http.StatusOK), func(cu *openapi.ContentUnit) {
		cu.Description = "New secret has been created"
	})
	forbidden(oc)
	oc.SetID("rotateOauthClient")
	oc.SetSummary("Rotate the oath client secret")
	oc.SetDescription("Generate a new secret")
	oc.SetTags(OAuthTag)
	par := []openapi3.ParameterOrRef{keyNameParameter(), oauthApiIdParameter()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

// Done
func invalidateOauthRefresh(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodDelete, "/tyk/oauth/refresh/{keyName}")
	if err != nil {
		return err
	}
	oc.SetTags(OAuthTag)
	oc.SetID("invalidateOAuthRefresh")
	oc.SetSummary("Invalidate OAuth refresh token")
	oc.SetDescription("It is possible to invalidate refresh tokens in order to manage OAuth client access more robustly.")
	statusNotFound(oc, "Returned when the API for this refresh token is not found")
	statusBadRequest(oc, "Returned when you fail to send the api_id or when OAuth is not enabled on the API")
	forbidden(oc)
	statusInternalServerError(oc, "internal server error")
	oc.AddRespStructure(new(apiModifyKeySuccess), openapi.WithHTTPStatus(http.StatusOK), func(cu *openapi.ContentUnit) {
		cu.Description = "Deleted"
	})
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{keyNameParameter(), requiredApiIdQuery()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

// /https://deploy-preview-4394--tyk-docs.netlify.app/docs/nightly/apim/
// Done
func updateOauthClient(r *openapi3.Reflector) error {
	// TODO:: in previous OAs this was '/tyk/oauth/clients/{apiID}' inquire
	oc, err := r.NewOperationContext(http.MethodPut, "/tyk/oauth/clients/{apiID}/{keyName}")
	if err != nil {
		return err
	}
	oc.AddReqStructure(new(gateway.NewClientRequest))
	// TODO:: we return error 500 instead of error 400
	statusInternalServerError(oc, "internal server error")
	forbidden(oc)
	statusNotFound(oc, "Returned when api with the api_id sent in the apiID parameter  doesn't exist or when the OAuth Client ID is not found")
	statusBadRequest(oc, "Returned when the policy access rights doesn't contain API this OAuth client belongs to")
	oc.AddRespStructure(new(gateway.NewClientRequest), openapi.WithHTTPStatus(http.StatusOK), func(cu *openapi.ContentUnit) {
		cu.Description = "OAuth client updated"
	})
	oc.SetID("updateOAuthClient")
	oc.SetSummary("Update OAuth metadata,redirecturi,description and Policy ID")
	oc.SetDescription("Allows you to update the metadata,redirecturi,description and Policy ID for an OAuth client.")
	oc.SetTags(OAuthTag)
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{keyNameParameter(), oauthApiIdParameter()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func getApisForOauthApp(r *openapi3.Reflector) error {
	// TODO:: check is again about org_id be required. After testing it seems it should be required even if it is empty
	// if i don't send the org_id another url is called instead.
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/oauth/clients/apis/{appID}")
	if err != nil {
		return err
	}
	oc.SetTags(OAuthTag)
	oc.SetID("getApisForOauthApp")
	oc.SetSummary("Get API IDs for APIS that use the specified client_id(appID) for OAuth")
	oc.SetDescription("Get all API IDs for APIs that have use_oauth2 enabled and use the client_id (appID) specified in the path parameter for OAuth2. You can use the org_id query parameter to specify from which organization you want the API IDs to be returned. To return APIs from all organizations, send org_id as an empty string.")
	forbidden(oc)
	oc.AddRespStructure(new([]string), openapi.WithHTTPStatus(http.StatusOK), func(cu *openapi.ContentUnit) {
		cu.Description = "Return an array of apis ids"
	})
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{appIDParameter(), requiredOrgIdForOauth()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func purgeLapsedOAuthTokens(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodDelete, "/tyk/oauth/tokens")
	if err != nil {
		return err
	}
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusUnprocessableEntity))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	oc.AddRespStructure(new(apiStatusMessage))
	oc.SetID("purgeLapsedOAuthTokens")
	oc.SetSummary("Purge lapsed OAuth tokens")
	oc.SetDescription("Purge scoped lapsed OAuth token")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{scopeQuery()}
	o3.Operation().WithParameters(par...)

	oc.SetTags(OAuthTag)
	return r.AddOperation(oc)
}

func listOAuthClients(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodDelete, "/tyk/oauth/clients/{apiID}")
	if err != nil {
		return err
	}
	oc.SetTags(OAuthTag)
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.AddRespStructure(new([]gateway.NewClientRequest), openapi.WithHTTPStatus(http.StatusOK))
	// TODO:: ask why 404 returns null
	oc.AddRespStructure(new(*[]gateway.NewClientRequest), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new([]gateway.NewClientRequest), openapi.WithHTTPStatus(http.StatusOK))
	oc.SetID("listOAuthClients")
	oc.SetSummary("List oAuth clients")
	oc.SetDescription("OAuth Clients are organised by API ID, and therefore are queried as such.")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{oauthApiIdParameter()}
	o3.Operation().WithParameters(par...)

	return r.AddOperation(oc)
}

func deleteOAuthClient(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodDelete, "/tyk/oauth/clients/{apiID}/{keyName}")
	if err != nil {
		return err
	}
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	oc.AddRespStructure(new(apiModifyKeySuccess), openapi.WithHTTPStatus(http.StatusOK), func(cu *openapi.ContentUnit) {
	})
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.SetTags(OAuthTag)
	oc.SetID("deleteOAuthClient")
	oc.SetSummary("Delete OAuth client")
	oc.SetDescription("Please note that tokens issued with the client ID will still be valid until they expire.")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{oauthApiIdParameter(), keyNameParameter()}
	o3.Operation().WithParameters(par...)

	return r.AddOperation(oc)
}

func getSingleOAuthClient(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/oauth/clients/{apiID}/{keyName}")
	if err != nil {
		return err
	}
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(gateway.NewClientRequest), openapi.WithHTTPStatus(http.StatusOK))
	// TODO::returned when basing dowritejsonfails
	// oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.SetID("getOAuthClient")
	oc.SetSummary("Get OAuth client")
	oc.SetDescription("Get OAuth client details")
	oc.SetTags(OAuthTag)
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{oauthApiIdParameter(), keyNameParameter()}
	o3.Operation().WithParameters(par...)

	return r.AddOperation(oc)
}

func getAuthClientTokens(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/oauth/clients/{apiID}/{keyName}/tokens")
	if err != nil {
		return err
	}
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	oc.AddRespStructure(jsonschema.OneOf(new(paginatedOAuthClientTokens), new([]gateway.OAuthClientToken)), openapi.WithHTTPStatus(http.StatusOK), func(cu *openapi.ContentUnit) {
		cu.Description = "Get a list of tokens"
	})
	oc.SetTags(OAuthTag)
	oc.SetID("getOAuthClientTokens")
	oc.SetSummary("List tokens")
	oc.SetDescription("This endpoint allows you to retrieve a list of all current tokens and their expiry date for a provided API ID and OAuth-client ID in the following format. This endpoint will work only for newly created tokens.\n        <br/>\n        <br/>\n        You can control how long you want to store expired tokens in this list using `oauth_token_expired_retain_period` gateway option, which specifies retain period for expired tokens stored in Redis. By default expired token not get removed. See <a href=\"https://tyk.io/docs/configure/tyk-gateway-configuration-options/#a-name-oauth-token-expired-retain-period-a-oauth-token-expired-retain-period\" target=\"_blank\">here</a> for more details.")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{oauthApiIdParameter(), keyNameParameter("The Client ID"), pageQuery()}
	o3.Operation().WithParameters(par...)

	return r.AddOperation(oc)
}

// Done
func revokeTokenHandler(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/oauth/revoke")
	if err != nil {
		return err
	}
	oc.AddReqStructure(new(struct {
		Token         string `json:"token" formData:"token" description:"token to be revoked" required:"true"`
		TokenTypeHint string `json:"token_type_hint" formData:"token_type_hint" description:"type of token to be revoked, if sent then the accepted values are access_token and refresh_token. String value and optional, of not provided then it will attempt to remove access and refresh tokens that matches"`
		ClientID      string `json:"client_id" formData:"client_id" description:"id of oauth client" required:"true"`
		OrgID         string `json:"org_id" formData:"org_id"`
	}), func(cu *openapi.ContentUnit) {
		cu.Description = "token revoked successfully"
	})
	oc.SetID("revokeSingleToken")
	oc.SetSummary("revoke token")
	oc.SetDescription("revoke a single token")
	statusBadRequest(oc, "Returned when you send a malformed request or when the oauth client doesn't exist")
	forbidden(oc)
	statusOKApiStatusMessage(oc)
	oc.SetTags(OAuthTag)
	return r.AddOperation(oc)
}

func revokeAllTokensHandler(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/oauth/revoke_all")
	if err != nil {
		return err
	}
	oc.AddReqStructure(new(struct {
		ClientSecret string `json:"client_secret" formData:"client_secret" required:"true" description:"OAuth client secret to ensure that its a valid operation"`
		ClientID     string `json:"client_id" formData:"client_id" description:"id of oauth client" required:"true"`
		OrgID        string `json:"org_id" formData:"org_id"`
	}))
	///TODO::this why is this 401 instead of badrequest
	statusUnauthorized(oc, "Bad request, form dmalforme or client secret and client id doesn't match")
	statusBadRequest(oc, "cannot parse form. Form malformed")
	statusNotFound(oc, "oauth client doesn't exist")
	statusOKApiStatusMessage(oc, "tokens revoked successfully")
	forbidden(oc)
	oc.SetTags(OAuthTag)
	oc.SetDescription("revoke all the tokens for a given oauth client")
	oc.SetSummary("revoke all client's tokens")
	oc.SetID("revokeAllTokens")

	return r.AddOperation(oc)
}

func keyNameParameter(description ...string) openapi3.ParameterOrRef {
	desc := "Refresh token"
	if len(description) != 0 {
		desc = description[0]
	}
	return openapi3.Parameter{In: openapi3.ParameterInPath, Name: "keyName", Required: &isRequired, Description: &desc, Schema: stringSchema()}.ToParameterOrRef()
}

func oauthApiIdParameter() openapi3.ParameterOrRef {
	return openapi3.Parameter{Description: stringPointerValue("The API ID"), In: openapi3.ParameterInPath, Name: "apiID", Required: &isRequired, Schema: stringSchema()}.ToParameterOrRef()
}

func requiredApiIdQuery() openapi3.ParameterOrRef {
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "api_id", Required: &isRequired, Description: stringPointerValue("The API id"), Schema: stringSchema()}.ToParameterOrRef()
}

func appIDParameter() openapi3.ParameterOrRef {
	return openapi3.Parameter{In: openapi3.ParameterInPath, Description: stringPointerValue("The Client ID"), Name: "appID", Required: &isRequired, Schema: stringSchema()}.ToParameterOrRef()
}

func scopeQuery() openapi3.ParameterOrRef {
	stringType := openapi3.SchemaTypeString
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "scope", Required: &isRequired, Schema: &openapi3.SchemaOrRef{
		Schema: &openapi3.Schema{
			Type: &stringType,
			Enum: []interface{}{"lapsed"},
		},
	}}.ToParameterOrRef()
}

func pageQuery() openapi3.ParameterOrRef {
	desc := "The page to return"
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "page", Required: &isOptional, Description: &desc, Schema: intSchema()}.ToParameterOrRef()
}

func requiredOrgIdForOauth() openapi3.ParameterOrRef {
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "orgID", Required: &isRequired, Schema: stringSchema()}.ToParameterOrRef()
}

func addOperations(r *openapi3.Reflector, operations ...func(r *openapi3.Reflector) error) error {
	for _, operation := range operations {
		err := operation(r)
		if err != nil {
			return err
		}
	}
	return nil
}

func forbidden(oc openapi.OperationContext, description ...string) {
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden), func(cu *openapi.ContentUnit) {
		cu.Description = "Attempting to access a protected api with an invalid or a missing X-Tyk-Authorization in the headers"
		if len(description) != 0 {
			cu.Description = description[0]
		}
	})
}

func statusNotFound(oc openapi.OperationContext, description ...string) {
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound), func(cu *openapi.ContentUnit) {
		if len(description) != 0 {
			cu.Description = description[0]
		}
	})
}

func statusBadRequest(oc openapi.OperationContext, description ...string) {
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest), func(cu *openapi.ContentUnit) {
		if len(description) != 0 {
			cu.Description = description[0]
		}
	})
}

func statusUnauthorized(oc openapi.OperationContext, description ...string) {
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusUnauthorized), func(cu *openapi.ContentUnit) {
		if len(description) != 0 {
			cu.Description = description[0]
		}
	})
}

func statusOKApiStatusMessage(oc openapi.OperationContext, description ...string) {
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusOK), func(cu *openapi.ContentUnit) {
		if len(description) != 0 {
			cu.Description = description[0]
		}
	})
}

func statusInternalServerError(oc openapi.OperationContext, description ...string) {
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError), func(cu *openapi.ContentUnit) {
		if len(description) != 0 {
			cu.Description = description[0]
		}
	})
}
