package gateway

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/lonelycode/osin"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/pkg/controlplane/oauth"
)

/*
Sample OAuth Flow:
-----------------

1. Request to /authorize
2. Tyk extracts all relevant data and pre-screens client_id, client_secret and redirect_uri
3. Instead of proxying the request it redirects the user to the login page on the resource with the client_id & secret as a POST (basically passed through)
4. Resource presents approve / deny window to user
5. If approve is clicked, resource pings oauth/authorise which is the actual authorize endpoint (requires admin key),
   this returns oauth details to resource as well as redirect URI which it can then redirect to
6. User is redirected to redirect URI with auth_code
7. Client makes auth request for bearer token
8. Client API makes all calls with bearer token

The storage, token issuance and client administration logic lives in
pkg/controlplane/oauth; this file keeps the gateway's HTTP handlers and the
types other gateway code refers to.
*/

// Types shared with the control-plane library.
type (
	// OAuthClient is a representation within an APISpec of a client
	OAuthClient = oauth.OAuthClient
	// OAuthClientToken is one entry of a client's token index.
	OAuthClientToken = oauth.OAuthClientToken
	// ExtendedOsinClientInterface is osin.Client plus a description.
	ExtendedOsinClientInterface = oauth.ExtendedOsinClientInterface
	// ExtendedOsinStorageInterface is osin.Storage plus Tyk's client and user operations.
	ExtendedOsinStorageInterface = oauth.ExtendedOsinStorageInterface
	// TykOsinServer subclasses osin.Server so we can reach the extended storage.
	TykOsinServer = oauth.Server
	// RedisOsinStorageInterface implements osin.Storage over Tyk's storage.
	RedisOsinStorageInterface = oauth.Storage
)

// Redis key prefixes for OAuth data, relative to oauth-data.<apiID>.
const (
	prefixAuth            = oauth.PrefixAuth
	prefixClient          = oauth.PrefixClient
	prefixAccess          = oauth.PrefixAccess
	prefixRefresh         = oauth.PrefixRefresh
	prefixClientset       = oauth.PrefixClientset
	prefixClientIndexList = oauth.PrefixClientIndexList
	prefixClientTokens    = oauth.PrefixClientTokens
)

// JSONToFormValues decodes a JSON body into r.Form when the content type is JSON.
var JSONToFormValues = oauth.JSONToFormValues

// OAuthNotificationType const to reduce risk of collisions
type OAuthNotificationType string

// Notification codes for new and refresh codes
const (
	newAccessToken     OAuthNotificationType = "new"
	refreshAccessToken OAuthNotificationType = "refresh"
)

// NewOAuthNotification is a notification sent to a
// web-hook when an access request or a refresh request comes in.
type NewOAuthNotification struct {
	AuthCode         string                `json:"auth_code"`
	NewOAuthToken    string                `json:"new_oauth_token"`
	RefreshToken     string                `json:"refresh_token"`
	OldRefreshToken  string                `json:"old_refresh_token"`
	NotificationType OAuthNotificationType `json:"notification_type"`
}

// OAuthHandlers are the HTTP Handlers that manage the Tyk OAuth flow
type OAuthHandlers struct {
	Manager OAuthManager
}

func (o *OAuthHandlers) generateOAuthOutputFromOsinResponse(osinResponse *osin.Response) []byte {
	return oauth.RenderResponse(osinResponse)
}

func (o *OAuthHandlers) notifyClientOfNewOauth(notification NewOAuthNotification) {
	log.Info("[OAuth] Notifying client host")
	go o.Manager.API.NotificationsDetails.SendRequest(false, 0, notification)
}

// HandleGenerateAuthCodeData handles a resource provider approving an OAuth request from a client
func (o *OAuthHandlers) HandleGenerateAuthCodeData(w http.ResponseWriter, r *http.Request) {
	// On AUTH grab session state data and add to UserData (not validated, not good!)
	sessionJSONData := r.FormValue("key_rules")
	if sessionJSONData == "" {
		log.Warning("Authorise request is missing key_rules in params, policy will be required!")
	}

	// Handle the authorisation and write the JSON output to the resource provider
	resp := o.Manager.HandleAuthorisation(r, true, sessionJSONData)
	code := http.StatusOK
	msg := o.generateOAuthOutputFromOsinResponse(resp)

	if resp.IsError {
		code = resp.ErrorStatusCode
		log.Error("[OAuth] OAuth response marked as error: ", resp)
	}
	w.WriteHeader(code)
	w.Write(msg)
}

// HandleAuthorizePassthrough handles a Client Auth request, first it checks if the client
// is OK (otherwise it blocks the request), then it forwards on to the resource providers approval URI
func (o *OAuthHandlers) HandleAuthorizePassthrough(w http.ResponseWriter, r *http.Request) {
	// Extract client data and check
	resp := o.Manager.HandleAuthorisation(r, false, "")
	if resp.IsError {
		log.Error("[OAuth] There was an error with the request: ", resp)
		// Something went wrong, write out the error details and kill the response
		doJSONWrite(w, resp.ErrorStatusCode, apiError(resp.StatusText))
		return
	}
	if r.Method == "GET" {
		loginURL := fmt.Sprintf("%s?%s", o.Manager.API.Oauth2Meta.AuthorizeLoginRedirect, r.URL.RawQuery)
		w.Header().Add("Location", loginURL)
	} else {
		w.Header().Add("Location", o.Manager.API.Oauth2Meta.AuthorizeLoginRedirect)
	}
	w.WriteHeader(307)
}

// HandleAccessRequest handles the OAuth 2.0 token or refresh access request, and wraps Tyk's own and Osin's OAuth handlers,
// returns a response to the client and notifies the provider of the access request (in order to track identity against
// OAuth tokens without revealing tokens before they are requested).
func (o *OAuthHandlers) HandleAccessRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	// Handle response
	resp := o.Manager.HandleAccess(r)
	msg := o.generateOAuthOutputFromOsinResponse(resp)

	if resp.IsError {
		// Something went wrong, write out the error details and kill the response
		w.WriteHeader(resp.ErrorStatusCode)
		w.Write(msg)
		return
	}

	// Ping endpoint with o_auth key and auth_key
	authCode := r.FormValue("code")
	oldRefreshToken := r.FormValue("refresh_token")
	log.Debug("AUTH CODE: ", authCode)
	newOauthToken := ""
	if resp.Output["access_token"] != nil {
		newOauthToken = resp.Output["access_token"].(string)
	}
	log.Debug("TOKEN: ", newOauthToken)
	refreshToken := ""
	if resp.Output["refresh_token"] != nil {
		refreshToken = resp.Output["refresh_token"].(string)
	}
	log.Debug("REFRESH: ", refreshToken)
	log.Debug("Old REFRESH: ", oldRefreshToken)

	notificationType := newAccessToken
	if oldRefreshToken != "" {
		notificationType = refreshAccessToken
	}

	newNotification := NewOAuthNotification{
		AuthCode:         authCode,
		NewOAuthToken:    newOauthToken,
		RefreshToken:     refreshToken,
		OldRefreshToken:  oldRefreshToken,
		NotificationType: notificationType,
	}

	o.notifyClientOfNewOauth(newNotification)

	w.WriteHeader(http.StatusOK)
	w.Write(msg)
}

// in compliance with https://tools.ietf.org/html/rfc7009#section-2.1
// ToDo: set an authentication mechanism
func (o *OAuthHandlers) HandleRevokeToken(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		doJSONWrite(w, http.StatusBadRequest, apiError("error parsing form. Form malformed"))
		return
	}

	token := r.PostFormValue("token")
	tokenTypeHint := r.PostFormValue("token_type_hint")

	if token == "" {
		doJSONWrite(w, http.StatusBadRequest, apiError(oauthTokenEmpty))
		return
	}

	RevokeToken(o.Manager.OsinServer.Storage, token, tokenTypeHint)
	doJSONWrite(w, http.StatusOK, apiOk("token revoked successfully"))
}

// RevokeToken removes an access and/or refresh token from a storage.
func RevokeToken(storage ExtendedOsinStorageInterface, token, tokenTypeHint string) {
	oauth.RevokeToken(storage, token, tokenTypeHint)
}

func (o *OAuthHandlers) HandleRevokeAllTokens(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		doJSONWrite(w, http.StatusBadRequest, apiError("error parsing form. Form malformed"))
		return
	}

	clientId := r.PostFormValue("client_id")
	secret := r.PostFormValue("client_secret")

	if clientId == "" {
		doJSONWrite(w, http.StatusUnauthorized, apiError(oauthClientIdEmpty))
		return
	}

	if secret == "" {
		doJSONWrite(w, http.StatusUnauthorized, apiError(oauthClientSecretEmpty))
		return
	}

	status, tokens, err := RevokeAllTokens(o.Manager.OsinServer.Storage, clientId, secret)
	if err != nil {
		doJSONWrite(w, status, apiError(err.Error()))
		return
	}

	n := Notification{
		Command: KeySpaceUpdateNotification,
		Payload: strings.Join(tokens, ","),
		Gw:      o.Manager.Gw,
	}
	o.Manager.Gw.MainNotifier.Notify(n)

	doJSONWrite(w, http.StatusOK, apiOk("tokens revoked successfully"))
}

// RevokeAllTokens removes every token of a client after checking its secret.
func RevokeAllTokens(storage ExtendedOsinStorageInterface, clientId, clientSecret string) (int, []string, error) {
	return oauth.RevokeAllTokens(storage, clientId, clientSecret, log)
}

// OAuthManager handles and wraps osin OAuth2 functions to handle authorise and access requests
type OAuthManager struct {
	API        *APISpec
	OsinServer *TykOsinServer
	Gw         *Gateway `json:"-"`
}

func (o *OAuthManager) Storage() ExtendedOsinStorageInterface {
	return o.OsinServer.Storage
}

// lib binds this manager to the control-plane implementation.
func (o *OAuthManager) lib() *oauth.Manager {
	return o.Gw.oauthManagerFor(o.API, o.OsinServer)
}

// HandleAuthorisation creates the authorisation data for the request
func (o *OAuthManager) HandleAuthorisation(r *http.Request, complete bool, session string) *osin.Response {
	return o.lib().HandleAuthorisation(r, complete, session)
}

// HandleAccess wraps an access request with osin's primitives
func (o *OAuthManager) HandleAccess(r *http.Request) *osin.Response {
	return o.lib().HandleAccess(r)
}

// TykOsinNewServer creates a new server instance, but uses an extended interface so we can SetClient() too.
func (gw *Gateway) TykOsinNewServer(config *osin.ServerConfig, storage ExtendedOsinStorageInterface) *TykOsinServer {
	return oauth.NewServer(config, storage, gw.controlPlaneKeys(), log)
}

func (gw *Gateway) purgeLapsedOAuthTokens() error {
	return gw.controlPlaneOAuth().PurgeLapsedTokens()
}
