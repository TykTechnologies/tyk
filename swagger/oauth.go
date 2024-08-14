package swagger

import (
	"net/http"

	"github.com/swaggest/jsonschema-go"
	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/gateway"
)

const (
	OAuthTag     = "OAuth"
	OAuthTagDesc = `Manage OAuth clients, and manage their tokens
`
)

func OAuthApi(r *openapi3.Reflector) error {
	addTag(OAuthTag, OAuthTagDesc, optionalTagParameters{})
	return addOperations(r, rotateOauthClientHandler, invalidateOauthRefresh,
		updateOauthClient, getApisForOauthApp, purgeLapsedOAuthTokens,
		deleteOAuthClient, getSingleOAuthClientDetails, getAuthClientTokens, revokeTokenHandler,
		createOauthClient, revokeAllTokensHandler, oAuthClientHandler,
	)
}

func updateOAuthClient(r *openapi3.Reflector) error {
	oc, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodPut,
		PathPattern: "/tyk/oauth/clients/{apiID}",
		OperationID: "updateoAuthClient",
		Tag:         OAuthTag,
	})
	if err != nil {
		return err
	}

	return oc.AddOperation()
}

func oAuthClientHandler(r *openapi3.Reflector) error {
	oc, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodGet,
		PathPattern: "/tyk/oauth/clients/{apiID}",
		OperationID: "listOAuthClients",
		Tag:         OAuthTag,
	})
	if err != nil {
		return err
	}
	oc.AddResp(nil, http.StatusNotFound, func(cu *openapi.ContentUnit) {
		cu.Description = "Api no found"
	})
	oc.SetSummary("List oAuth clients")
	oc.SetDescription("OAuth Clients are organised by API ID, and therefore are queried as such.")
	oc.AddPathParameter("apiID", "The API ID", OptionalParameterValues{
		Example: valueToInterface("1bd5c61b0e694082902cf15ddcc9e6a7"),
	})
	oc.AddRespWithExample(clientItems, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "Get OAuth client details or a list of OAuth clients"
	})

	return oc.AddOperation()
}

// Done
func createOauthClient(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodPost,
		PathPattern: "/tyk/oauth/clients/create",
		OperationID: "createOAuthClient",
		Tag:         OAuthTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	client := clientItems[0]
	client.APIID = ""
	op.AddReqWithExample(clientItems[0])
	op.AddRespWithExample(client, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "Client created"
	})
	op.AddGenericErrorResponse(http.StatusInternalServerError, "Unmarshalling failed", func(cu *openapi.ContentUnit) {
		cu.Description = "Unmarshalling failed"
	})
	op.StatusBadRequest("API doesn't exist", func(cu *openapi.ContentUnit) {
		cu.Description = "Api Not found"
	})
	// TODO::ask why we return 500 instead of 400 for wrong body
	oc.SetSummary("Create new OAuth client")
	oc.SetDescription("Any OAuth keys must be generated with the help of a client ID. These need to be pre-registered with Tyk before they can be used (in a similar vein to how you would register your app with Twitter before attempting to ask user permissions using their API).\n        <br/><br/>\n        <h3>Creating OAuth clients with Access to Multiple APIs</h3>\n        New from Tyk Gateway 2.6.0 is the ability to create OAuth clients with access to more than one API. If you provide the api_id it works the same as in previous releases. If you don't provide the api_id the request uses policy access rights and enumerates APIs from their setting in the newly created OAuth-client.\n")
	return op.AddOperation()
}

// Done
func rotateOauthClientHandler(r *openapi3.Reflector) error {
	// TODO::find summary and description for this
	// TODO::this is not in  the old swagger
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodPut,
		PathPattern: "/tyk/oauth/clients/{apiID}/{keyName}/rotate",
		OperationID: "rotateOauthClient",
		Tag:         OAuthTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	op.AddPathParameter("apiID", "The API id", OptionalParameterValues{
		Example: valueToInterface("b84fe1a04e5648927971c0557971565c"),
	})
	op.AddPathParameter("keyName", "The Client ID", OptionalParameterValues{
		Example: valueToInterface("2a06b398c17f46908de3dffcb71ef87df"),
	})
	op.StatusNotFound("API doesn't exist")
	op.StatusInternalServerError("Failure in storing client data")
	client := clientItems[0]
	client.APIID = ""
	op.AddRespWithExample(client, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "New secret has been created"
	})
	oc.SetSummary("Rotate the oath client secret")
	oc.SetDescription("Generate a new secret")
	return op.AddOperation()
}

// Done
func invalidateOauthRefresh(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodDelete,
		PathPattern: "/tyk/oauth/refresh/{keyName}",
		OperationID: "invalidateOAuthRefresh",
		Tag:         OAuthTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	oc.SetSummary("Invalidate OAuth refresh token")
	oc.SetDescription("It is possible to invalidate refresh tokens in order to manage OAuth client access more robustly.")
	op.AddPathParameter("keyName", "The Client ID", OptionalParameterValues{
		Example: valueToInterface("2a06b398c17f46908de3dffcb71ef87df"),
	})
	op.AddQueryParameter("api_id", "The API id", OptionalParameterValues{
		Required: PointerValue(true),
		Example:  valueToInterface("b84fe1a04e5648927971c0557971565c"),
	})
	op.StatusNotFound("API for this refresh token not found")
	op.StatusBadRequest("Missing parameter api_id", func(cu *openapi.ContentUnit) {
		cu.Description = "missing api_Id query parameter"
	})
	op.StatusInternalServerError("Failed to invalidate refresh token")
	op.AddRespWithExample(apiModifyKeySuccess{
		Key:    "2a06b398c17f46908de3dffcb71ef87df",
		Status: "ok",
		Action: "deleted",
	}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "Deleted"
	})
	return op.AddOperation()
}

// Done
func updateOauthClient(r *openapi3.Reflector) error {
	// TODO:: in previous OAs this was '/tyk/oauth/clients/{apiID}' inquire
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodPut,
		PathPattern: "/tyk/oauth/clients/{apiID}/{keyName}",
		OperationID: "updateOAuthClient",
		Tag:         OAuthTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	op.AddGenericErrorResponse(http.StatusInternalServerError, "Unmarshalling failed", func(cu *openapi.ContentUnit) {
		cu.Description = "malformed request body"
	})
	op.StatusNotFound("API doesn't exist")
	client := clientItems[0]
	client.Description = "changed description sample"
	op.AddReqWithExample(client)
	// TODO:: we return error 500 instead of error 400
	op.StatusBadRequest("Policy access rights doesn't contain API this OAuth client belongs to")
	replydata := clientItems[0]
	replydata.Description = "changed description sample"
	replydata.APIID = ""
	op.AddRespWithExample(replydata, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "OAuth client updated"
	})
	oc.SetSummary("Update OAuth metadata,redirecturi,description and Policy ID")
	oc.SetDescription("Allows you to update the metadata,redirecturi,description and Policy ID for an OAuth client.")
	op.AddPathParameter("apiID", "The API id", OptionalParameterValues{
		Example: valueToInterface("b84fe1a04e5648927971c0557971565c"),
	})
	op.AddPathParameter("keyName", "The Client ID", OptionalParameterValues{
		Example: valueToInterface("2a06b398c17f46908de3dffcb71ef87df"),
	})
	return op.AddOperation()
}

func getApisForOauthApp(r *openapi3.Reflector) error {
	// TODO:: check is again about org_id be required. After testing it seems it should be required even if it is empty
	// if i don't send the org_id another url is called instead.
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodGet,
		PathPattern: "/tyk/oauth/clients/apis/{appID}",
		OperationID: "getApisForOauthApp",
		Tag:         OAuthTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	oc.SetSummary("Get API IDs for APIS that use the specified client_id(appID) for OAuth")
	oc.SetDescription("Get all API IDs for APIs that have use_oauth2 enabled and use the client_id (appID) specified in the path parameter for OAuth2. You can use the org_id query parameter to specify from which organization you want the API IDs to be returned. To return APIs from all organizations, send org_id as an empty string.")
	op.AddPathParameter("appID", "The Client ID", OptionalParameterValues{
		Example: valueToInterface("2a06b398c17f46908de3dffcb71ef87df"),
	})
	op.AddQueryParameter("orgID", "The Org Id", OptionalParameterValues{})
	op.AddResponseWithSeparateExample(new([]string), http.StatusOK, []string{"b84fe1a04e5648927971c0557971565c"}, func(cu *openapi.ContentUnit) {
		cu.Description = "Return an array of apis ids"
	})
	return op.AddOperation()
}

// Done
func purgeLapsedOAuthTokens(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodDelete,
		PathPattern: "/tyk/oauth/tokens",
		OperationID: "purgeLapsedOAuthTokens",
		Tag:         OAuthTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	// TODO::check description for this
	op.AddQueryParameter("scope", "purge lapsed tokens", OptionalParameterValues{
		Required: PointerValue(true),
		Example:  valueToInterface("lapsed"),
		Enum:     []interface{}{"lapsed"},
	})
	op.AddGenericErrorResponse(http.StatusUnprocessableEntity, "scope parameter is required", func(cu *openapi.ContentUnit) {
		cu.Description = "Missing lapsed query parameter"
	})
	op.StatusBadRequest("unknown scope", func(cu *openapi.ContentUnit) {
		cu.Description = "Sending a value other than lapsed in scope query"
	})
	op.StatusInternalServerError("error purging lapsed tokens")
	op.AddRespWithExample(apiStatusMessage{"ok", "lapsed tokens purged"}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "lapsed tokens purged successfully"
	})
	oc.SetSummary("Purge lapsed OAuth tokens")
	oc.SetDescription("Purge all lapsed OAuth token")
	return op.AddOperation()
}

// Done
func deleteOAuthClient(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodDelete,
		PathPattern: "/tyk/oauth/clients/{apiID}/{keyName}",
		OperationID: "deleteOAuthClient",
		Tag:         OAuthTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	op.StatusNotFound("OAuth Client ID not found", func(cu *openapi.ContentUnit) {
		cu.Description = "Not found"
	})
	op.StatusInternalServerError("Delete failed")
	op.AddRespWithExample(apiModifyKeySuccess{
		Key:    "2a06b398c17f46908de3dffcb71ef87df",
		Status: "ok",
		Action: "deleted",
	}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "OAuth client deleted"
	})
	oc.SetSummary("Delete OAuth client")
	oc.SetDescription("Please note that tokens issued with the client ID will still be valid until they expire.")
	op.AddPathParameter("apiID", "The API id", OptionalParameterValues{
		Example: valueToInterface("b84fe1a04e5648927971c0557971565c"),
	})
	op.AddPathParameter("keyName", "The Client ID", OptionalParameterValues{
		Example: valueToInterface("2a06b398c17f46908de3dffcb71ef87df"),
	})
	return op.AddOperation()
}

// Done
func getSingleOAuthClientDetails(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodGet,
		PathPattern: "/tyk/oauth/clients/{apiID}/{keyName}",
		OperationID: "getOAuthClient",
		Tag:         OAuthTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	op.StatusNotFound("OAuth Client ID not found", func(cu *openapi.ContentUnit) {
		cu.Description = "OAuth Client not found"
	})

	replydata := clientItems[0]
	replydata.Description = "changed description sample"
	replydata.APIID = ""
	op.AddRespWithExample(replydata, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "OAuth client details"
	})
	oc.SetID("getOAuthClient")
	oc.SetSummary("Get OAuth client")
	oc.SetDescription("Get OAuth client details tied to an api")
	op.AddPathParameter("apiID", "The API id", OptionalParameterValues{
		Example: valueToInterface("b84fe1a04e5648927971c0557971565c"),
	})
	op.AddPathParameter("keyName", "The Client ID", OptionalParameterValues{
		Example: valueToInterface("2a06b398c17f46908de3dffcb71ef87df"),
	})

	return op.AddOperation()
}

// done
func getAuthClientTokens(r *openapi3.Reflector) error {
	// TODO::this was different in previous versions it only returned one response type
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodGet,
		PathPattern: "/tyk/oauth/clients/{apiID}/{keyName}/tokens",
		OperationID: "getOAuthClientTokens",
		Tag:         OAuthTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	op.AddPathParameter("apiID", "The API id", OptionalParameterValues{
		Example: valueToInterface("b84fe1a04e5648927971c0557971565c"),
	})
	op.AddPathParameter("keyName", "The Client ID", OptionalParameterValues{
		Example: valueToInterface("2a06b398c17f46908de3dffcb71ef87df"),
	})
	op.StatusNotFound("OAuth Client ID not found", func(cu *openapi.ContentUnit) {
		cu.Description = "OAuth Client ID not found"
	})
	op.StatusInternalServerError("Get client tokens failed")
	op.AddRespWithRefExamples(http.StatusOK, jsonschema.OneOf(new(paginatedOAuthClientTokens), new([]gateway.OAuthClientToken)), []multipleExamplesValues{
		{
			key:         paginatedTokenExample,
			httpStatus:  200,
			Summary:     "Paginated tokens when page query parameter is sent",
			exampleType: Component,
			ref:         paginatedTokenExample,
			hasExample:  true,
		},
		{
			key:         tokenListExample,
			httpStatus:  200,
			Summary:     "List of tokes",
			exampleType: Component,
			ref:         tokenListExample,
			hasExample:  true,
		},
	}, func(cu *openapi.ContentUnit) {
		cu.Description = "Tokens returned successfully."
	})

	oc.SetSummary("List tokens for a provided API ID and OAuth-client ID")
	oc.SetDescription("This endpoint allows you to retrieve a list of all current tokens and their expiry date for a provided API ID and OAuth-client ID .If page query parameter is sent the tokens will be paginated. This endpoint will work only for newly created tokens.\n        <br/>\n        <br/>\n        You can control how long you want to store expired tokens in this list using `oauth_token_expired_retain_period` gateway option, which specifies retain period for expired tokens stored in Redis. By default expired token not get removed. See <a href=\"https://tyk.io/docs/configure/tyk-gateway-configuration-options/#a-name-oauth-token-expired-retain-period-a-oauth-token-expired-retain-period\" target=\"_blank\">here</a> for more details.")
	op.AddPageQueryParameter()
	return op.AddOperation()
}

// Done
func revokeTokenHandler(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodPost,
		PathPattern: "/tyk/oauth/revoke",
		OperationID: "revokeSingleToken",
		Tag:         OAuthTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	oc.AddReqStructure(new(struct {
		Token         string `json:"token" formData:"token" description:"token to be revoked" required:"true" example:"eyJvcmciOiI1ZTIwOTFjNGQ0YWVmY2U2MGMwNGZiOTIiLCJpZCI6IjIyODQ1NmFjNmJlMjRiMzI5MTIyOTdlODQ5NTc4NjJhIiwiaCI6Im11cm11cjY0In0="`
		TokenTypeHint string `json:"token_type_hint" formData:"token_type_hint" description:"type of token to be revoked, if sent then the accepted values are access_token and refresh_token. String value and optional, of not provided then it will attempt to remove access and refresh tokens that matches" example:"access_token"`
		ClientID      string `json:"client_id" formData:"client_id" description:"id of oauth client" required:"true" example:"2a06b398c17f46908de3dffcb71ef87df"`
		OrgID         string `json:"org_id" formData:"org_id" example:"6492f66e6ebbc56c6a6bf022"`
	}), func(cu *openapi.ContentUnit) {
		cu.Description = "token revoked successfully"
	})
	op.StatusBadRequest("cannot parse form. Form malformed", func(cu *openapi.ContentUnit) {
		cu.Description = "malformed form data"
	})
	op.AddGenericStatusOk("token revoked successfully", func(cu *openapi.ContentUnit) {
		cu.Description = "token revoked"
	})
	oc.SetSummary("revoke token")
	oc.SetDescription("revoke a single token")
	return op.AddOperation()
}

// Done
func revokeAllTokensHandler(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodPost,
		PathPattern: "/tyk/oauth/revoke_all",
		OperationID: "revokeAllTokens",
		Tag:         OAuthTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	oc.AddReqStructure(new(struct {
		ClientSecret string `json:"client_secret" formData:"client_secret" required:"true" description:"OAuth client secret to ensure that its a valid operation" example:"MmQwNTI5NGQtYjU0YS00NjMyLWIwZjktNTZjY2M1ZjhjYWY0"`
		ClientID     string `json:"client_id" formData:"client_id" description:"id of oauth client" required:"true" example:"2a06b398c17f46908de3dffcb71ef87df"`
		OrgID        string `json:"org_id" formData:"org_id" example:"6492f66e6ebbc56c6a6bf022"`
	}))
	op.AddGenericStatusOk("tokens revoked successfully", func(cu *openapi.ContentUnit) {
		cu.Description = "tokens revoked"
	})
	op.AddGenericErrorResponse(http.StatusUnauthorized, "client_id is required", func(cu *openapi.ContentUnit) {
		cu.Description = "missing client id"
	})
	op.AddGenericErrorResponse(http.StatusNotFound, "oauth client doesn't exist", func(cu *openapi.ContentUnit) {
		cu.Description = "not found"
	})
	op.StatusBadRequest("cannot parse form. Form malformed")
	///TODO::why is this 401 instead of badRequest
	oc.SetDescription("Revoke all the tokens for a given oauth client")
	oc.SetSummary("Revoke all client's tokens")
	return op.AddOperation()
}

var clientItems = []gateway.NewClientRequest{
	{
		ClientID:          "2a06b398c17f46908de3dffcb71ef87df",
		ClientRedirectURI: "https://httpbin.org/ip",
		ClientSecret:      "MmQwNTI5NGQtYjU0YS00NjMyLWIwZjktNTZjY2M1ZjhjYWY0",
		MetaData: map[string]interface{}{
			"user_id": "362b3fb9a1d5e4f00017226f5",
		},
		Description: "google client",
		APIID:       "b84fe1a04e5648927971c0557971565c",
	},
}

var listTokens = []gateway.OAuthClientToken{
	{
		Token:   "5a7d110be6355b0c071cc339327563cb45174ae387f52f87a80d2496",
		Expires: 1518158407,
	},
	{
		Token:   "5a7d110be6355b0c071cc33988884222b0cf436eba7979c6c51d6dbd",
		Expires: 1518158594,
	},
	{
		Token:   "5a7d110be6355b0c071cc33990bac8b5261041c5a7d585bff291fec4",
		Expires: 1518158638,
	},
	{
		Token:   "5a7d110be6355b0c071cc339a66afe75521f49388065a106ef45af54",
		Expires: 1518159792,
	},
}
