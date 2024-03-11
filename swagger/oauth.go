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

func createOauthClient(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/oauth/clients/create")
	if err != nil {
		return err
	}
	oc.SetTags(OAuthTag)
	oc.AddReqStructure(new(gateway.NewClientRequest))
	oc.AddRespStructure(new(gateway.NewClientRequest))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	// TODO::ask why we return 500 instead of 400 for wrong body
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	oc.SetID("createOAuthClient")
	oc.SetSummary("Create new OAuth client")
	oc.SetDescription("Any OAuth keys must be generated with the help of a client ID. These need to be pre-registered with Tyk before they can be used (in a similar vein to how you would register your app with Twitter before attempting to ask user permissions using their API).\n        <br/><br/>\n        <h3>Creating OAuth clients with Access to Multiple APIs</h3>\n        New from Tyk Gateway 2.6.0 is the ability to create OAuth clients with access to more than one API. If you provide the api_id it works the same as in previous releases. If you don't provide the api_id the request uses policy access rights and enumerates APIs from their setting in the newly created OAuth-client.\n")
	return r.AddOperation(oc)
}

func rotateOauthClientHandler(r *openapi3.Reflector) error {
	// TODO::find summary and description for this
	oc, err := r.NewOperationContext(http.MethodPut, "/tyk/oauth/clients/{apiID}/{keyName}/rotate")
	if err != nil {
		return err
	}
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	oc.AddRespStructure(new(gateway.NewClientRequest), openapi.WithHTTPStatus(http.StatusOK))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.SetID("rotateOauthClient")
	oc.SetSummary("Rotate the oath client")
	oc.SetTags(OAuthTag)
	par := []openapi3.ParameterOrRef{keyNameParameter(), oauthApiIdParameter()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func invalidateOauthRefresh(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodDelete, "/tyk/oauth/refresh/{keyName}")
	if err != nil {
		return err
	}
	oc.SetTags(OAuthTag)
	oc.SetID("invalidateOAuthRefresh")
	oc.SetSummary("Invalidate OAuth refresh token")
	oc.SetDescription("It is possible to invalidate refresh tokens in order to manage OAuth client access more robustly.")
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	oc.AddRespStructure(new(apiModifyKeySuccess), openapi.WithHTTPStatus(http.StatusOK))
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{keyNameParameter(), requiredApiIdQuery()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func updateOauthClient(r *openapi3.Reflector) error {
	// TODO:: in previous OAs this was '/tyk/oauth/clients/{apiID}' inquire
	oc, err := r.NewOperationContext(http.MethodPut, "/tyk/oauth/clients/{apiID}/{keyName}")
	if err != nil {
		return err
	}
	oc.AddReqStructure(new(gateway.NewClientRequest))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	oc.AddRespStructure(new(gateway.NewClientRequest), openapi.WithHTTPStatus(http.StatusOK))
	oc.SetID("updateOAuthClient")
	oc.SetSummary("Update OAuth metadata and Policy ID")
	oc.SetDescription("Allows you to update the metadata and Policy ID for an OAuth client.")
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
	// TODO::This is has org_id as form value need to find a way to fix it
	// TODO:: Go over this again
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/oauth/clients/apis/{appID}")
	if err != nil {
		return err
	}
	oc.SetTags(OAuthTag)
	oc.SetID("getApisForOauthApp")
	oc.SetSummary("Get Apis for Oauth app")
	oc.SetDescription("Get Apis for Oauth app")
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.AddRespStructure(new([]string), openapi.WithHTTPStatus(http.StatusOK))
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{appIDParameter()}
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

func revokeTokenHandler(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/oauth/revoke")
	if err != nil {
		return err
	}
	// TODO::This is totally wrong find out how to do it
	oc.AddReqStructure(new(struct {
		Token         string `json:"token" formData:"token" description:"token to be revoked" required:"true"`
		TokenTypeHint string `json:"token_type_hint" formData:"token_type_hint" description:"type of token to be revoked, if sent then the accepted values are access_token and refresh_token. String value and optional, of not provided then it will attempt to remove access and refresh tokens that matches"`
		ClientID      string `json:"client_id" formData:"client_id" description:"id of oauth client" required:"true"`
		OrgID         string `json:"org_id" formData:"org_id"`
	}), func(cu *openapi.ContentUnit) {
	})
	oc.SetID("revokeSingleToken")
	oc.SetSummary("revoke token")
	oc.SetDescription("revoke a single token")
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
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
	statusUnauthorized(oc, "Bad request, form malformed or client secret and client id doesn't match")
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
	return openapi3.Parameter{In: openapi3.ParameterInPath, Name: "apiID", Required: &isRequired, Schema: stringSchema()}.ToParameterOrRef()
}

func requiredApiIdQuery() openapi3.ParameterOrRef {
	desc := "The API id"
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "api_id", Required: &isRequired, Description: &desc, Schema: stringSchema()}.ToParameterOrRef()
}

func appIDParameter() openapi3.ParameterOrRef {
	return openapi3.Parameter{In: openapi3.ParameterInPath, Name: "appID", Required: &isRequired, Schema: stringSchema()}.ToParameterOrRef()
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
		cu.Description = "Attempted administrative access with invalid or missing key!"
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
