package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	osin "github.com/lonelycode/osin"
	"github.com/TykTechnologies/tyk/apispec"
	"github.com/TykTechnologies/tyk/session"
	"github.com/TykTechnologies/tyk/session_handler"
	"github.com/TykTechnologies/tyk/storage"
)

/*

Sample Oaut Flow:
-----------------

1. Request to /authorize
2. Tyk extracts all relevant data and pre-screens client_id, client_secret and redirect_uri
3. Instead of proxying the request it redirects the user to the login page on the resource with the client_id & secret as a POST (basically passed through)
4. Resource presents approve / deny window to user
5. If approve is clicked, resource pings oauth/authorise which is the actual authorize endpoint (requires admin key),
   this returns oauth details to resource as well as redirect URI which it can then redirec to
6. User is redirected to redirect URI with auth_code
7. Client makes auth request for bearer token
8. Client API makes all calls with bearer token

Effort required by Resource Owner:
1. Create a login & approve/deny page
2. Send an API request to Tyk to generate an auth_code
3. Create endpoint to accept key change notifications

*/

// OAuthClient is a representation within an APISpec of a client
type OAuthClient struct {
	ClientID          string `json:"id"`
	ClientSecret      string `json:"secret"`
	ClientRedirectURI string `json:"redirecturi"`
	UserData          string `json:",omitempty"`
	PolicyID          string `json:"policyid"`
}

func (oc *OAuthClient) GetId() string {
	return oc.ClientID
}

func (oc *OAuthClient) GetSecret() string {
	return oc.ClientSecret
}

func (oc *OAuthClient) GetRedirectUri() string {
	return oc.ClientRedirectURI
}

func (oc *OAuthClient) GetUserData() interface{} {
	return oc.UserData
}

func (oc *OAuthClient) GetPolicyID() string {
	return oc.PolicyID
}

// OAuthNotificationType const to reduce risk of colisions
type OAuthNotificationType string

// Notifcation codes for new and refresh codes
const (
	newAccessToken     OAuthNotificationType = "new"
	refreshAccessToken OAuthNotificationType = "refresh"
)

// NewOAuthNotification is a notification sent to a
// webhook when an access request or a refresh request comes in.
type NewOAuthNotification struct {
	AuthCode         string                `json:"auth_code"`
	NewOAuthToken    string                `json:"new_oauth_token"`
	RefreshToken     string                `json:"refresh_token"`
	OldRefreshToken  string                `json:"old_refresh_token"`
	NotificationType OAuthNotificationType `json:"notification_type"`
}

// These enums fix the prefix to use when storing various OAuth keys and data, since we
// delegate everything to the osin framework
const (
	prefixAuth      = "oauth-authorize."
	prefixClient    = "oauth-clientid."
	prefixAccess    = "oauth-access."
	prefixRefresh   = "oauth-refresh."
	prefixClientset = "oauth-clientset."
)

// Refactors
type ExtendedOsinStorageInterface = apispec.ExtendedOsinStorageInterface
type TykOsinServer = apispec.TykOsinServer
type OAuthManager = apispec.OAuthManager

// TykOsinNewServer creates a new server instance, but uses an extended interface so we can SetClient() too.
func TykOsinNewServer(config *osin.ServerConfig, storage ExtendedOsinStorageInterface) *TykOsinServer {

	tokenGen := AccessTokenGenTyk{keyGen, generateSessionFromPolicy}

	overrideServer := TykOsinServer{
		Config:            config,
		Storage:           storage,
		AuthorizeTokenGen: &osin.AuthorizeTokenGenDefault{},
		AccessTokenGen:    tokenGen,
	}

	overrideServer.Server.Config = config
	overrideServer.Server.Storage = storage
	overrideServer.Server.AuthorizeTokenGen = overrideServer.AuthorizeTokenGen
	overrideServer.Server.AccessTokenGen = tokenGen

	return &overrideServer
}

// OAuthHandlers are the HTTP Handlers that manage the Tyk OAuth flow
type OAuthHandlers struct {
	Manager OAuthManager
}

func (o *OAuthHandlers) generateOAuthOutputFromOsinResponse(osinResponse *osin.Response) []byte {

	// TODO: Might need to clear this out
	if osinResponse.Output["state"] == "" {
		log.Debug("Removing state")
		delete(osinResponse.Output, "state")
	}

	redirect, err := osinResponse.GetRedirectUrl()
	if err == nil {
		// Hack to inject redirect into response
		osinResponse.Output["redirect_to"] = redirect
	}

	respData, err := json.Marshal(&osinResponse.Output)
	if err != nil {
		return nil
	}
	return respData
}

func (o *OAuthHandlers) notifyClientOfNewOauth(notification NewOAuthNotification) {
	log.Info("[OAuth] Notifying client host")
	go o.Manager.API.NotificationsDetails.SendRequest(false, 0, notification)
}

// HandleGenerateAuthCodeData handles a resource provider approving an OAuth request from a client
func (o *OAuthHandlers) HandleGenerateAuthCodeData(w http.ResponseWriter, r *http.Request) {
	// On AUTH grab session state data and add to UserData (not validated, not good!)
	sessionStateJSONData := r.FormValue("key_rules")
	if sessionStateJSONData == "" {
		log.Warning("Authorise request is missing key_rules in params, policy will be required!")
	}

	// Handle the authorisation and write the JSON output to the resource provider
	resp := o.Manager.HandleAuthorisation(r, true, sessionStateJSONData)
	code := 200
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
		log.Error("There was an error with the request: ", resp)
		// Something went wrong, write out the error details and kill the response
		doJSONWrite(w, resp.ErrorStatusCode, apiError(resp.StatusText))
		return
	}
	if r.Method == "GET" {
		var buffer bytes.Buffer
		buffer.WriteString(o.Manager.API.Oauth2Meta.AuthorizeLoginRedirect)
		buffer.WriteString("?client_id=")
		buffer.WriteString(r.FormValue("client_id"))
		buffer.WriteString("&redirect_uri=")
		buffer.WriteString(r.FormValue("redirect_uri"))
		buffer.WriteString("&response_type=")
		buffer.WriteString(r.FormValue("response_type"))
		w.Header().Add("Location", buffer.String())
	} else {
		w.Header().Add("Location", o.Manager.API.Oauth2Meta.AuthorizeLoginRedirect)
	}
	w.WriteHeader(307)

}

// HandleAccessRequest handles the OAuth 2.0 token or refresh access request, and wraps Tyk's own and Osin's OAuth handlers,
// returns a response to the client and notifies the provider of the access request (in order to track identity against
// OAuth tokens without revealing tokens before they are requested).
func (o *OAuthHandlers) HandleAccessRequest(w http.ResponseWriter, r *http.Request) {
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

	w.WriteHeader(200)
	w.Write(msg)
}


// TODO: Refactor this to move prefix handling into a checker method, then it can be an unexported setting in the struct.
// RedisOsinStorageInterface implements osin.Storage interface to use Tyk's own storage mechanism
type RedisOsinStorageInterface struct {
	store          storage.StorageHandler
	sessionManager session_handler.SessionHandler
}

func (r *RedisOsinStorageInterface) Clone() osin.Storage {
	return r
}

func (r *RedisOsinStorageInterface) Close() {}

// GetClient will retrieve client data
func (r *RedisOsinStorageInterface) GetClient(id string) (osin.Client, error) {
	key := prefixClient + id

	log.Info("Getting client ID:", id)

	clientJSON, err := r.store.GetKey(key)
	if err != nil {
		log.Errorf("Failure retreiving client ID key %q: %v", key, err)
		return nil, err
	}

	client := new(OAuthClient)
	if err := json.Unmarshal([]byte(clientJSON), &client); err != nil {
		log.Error("Couldn't unmarshal OAuth client object: ", err)
	}

	return client, nil
}

// GetClientNoPrefix will retrieve client data, but not assign a prefix - this is an unfortunate hack,
// but we don't want to change the signature in Osin for GetClient to support the odd Redis prefixing
func (r *RedisOsinStorageInterface) GetClientNoPrefix(id string) (osin.Client, error) {

	key := id

	clientJSON, err := r.store.GetKey(key)

	if err != nil {
		log.Error("Failure retreiving client ID key: ", err)
		return nil, err
	}

	client := new(OAuthClient)
	if err := json.Unmarshal([]byte(clientJSON), &client); err != nil {
		log.Error("Couldn't unmarshal OAuth client object: ", err)
	}

	return client, nil
}

// GetClients will retrieve a list of clients for a prefix
func (r *RedisOsinStorageInterface) GetClients(filter string, ignorePrefix bool) ([]osin.Client, error) {
	key := prefixClient + filter
	if ignorePrefix {
		key = filter
	}

	var clientJSON map[string]string
	if !globalConf.Storage.EnableCluster {
		clientJSON = r.store.GetKeysAndValuesWithFilter(key)
	} else {
		keyForSet := prefixClientset + prefixClient // Org ID
		var err error
		if clientJSON, err = r.store.GetSet(keyForSet); err != nil {
			return nil, err
		}
	}

	theseClients := []osin.Client{}
	for _, clientJSON := range clientJSON {
		client := new(OAuthClient)
		if err := json.Unmarshal([]byte(clientJSON), &client); err != nil {
			log.Error("Couldn't unmarshal OAuth client object: ", err)
			return nil, err
		}
		theseClients = append(theseClients, client)
	}

	return theseClients, nil
}

// SetClient creates client data
func (r *RedisOsinStorageInterface) SetClient(id string, client osin.Client, ignorePrefix bool) error {
	clientDataJSON, err := json.Marshal(client)

	if err != nil {
		log.Error("Couldn't marshal client data: ", err)
		return err
	}

	key := prefixClient + id

	if ignorePrefix {
		key = id
	}

	log.Debug("CREATING: ", key)

	r.store.SetKey(key, string(clientDataJSON), 0)

	log.Debug("Storing copy in set")

	keyForSet := prefixClientset + prefixClient // Org ID
	r.store.AddToSet(keyForSet, string(clientDataJSON))
	return nil
}

// DeleteClient Removes a client from the system
func (r *RedisOsinStorageInterface) DeleteClient(id string, ignorePrefix bool) error {
	key := prefixClient + id
	if ignorePrefix {
		key = id
	}

	// Get the raw vals:
	clientJSON, err := r.store.GetKey(key)
	if err == nil {
		log.Debug("Removing from set")
		keyForSet := prefixClientset + prefixClient // Org ID
		r.store.RemoveFromSet(keyForSet, clientJSON)
	}

	r.store.DeleteKey(key)

	return nil
}

// SaveAuthorize saves authorisation data to REdis
func (r *RedisOsinStorageInterface) SaveAuthorize(authData *osin.AuthorizeData) error {
	authDataJSON, err := json.Marshal(&authData)
	if err != nil {
		return err
	}
	key := prefixAuth + authData.Code
	log.Debug("Saving auth code: ", key)
	r.store.SetKey(key, string(authDataJSON), int64(authData.ExpiresIn))
	return nil

}

// LoadAuthorize loads auth data from redis
func (r *RedisOsinStorageInterface) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	key := prefixAuth + code
	log.Debug("Loading auth code: ", key)
	authJSON, err := r.store.GetKey(key)

	if err != nil {
		log.Error("Failure retreiving auth code key: ", err)
		return nil, err
	}

	authData := osin.AuthorizeData{}
	authData.Client = new(OAuthClient)
	if err := json.Unmarshal([]byte(authJSON), &authData); err != nil {
		log.Error("Couldn't unmarshal OAuth auth data object (LoadAuthorize): ", err)
		return nil, err
	}

	return &authData, nil
}

// RemoveAuthorize removes authorisation keys from redis
func (r *RedisOsinStorageInterface) RemoveAuthorize(code string) error {
	key := prefixAuth + code
	r.store.DeleteKey(key)
	return nil
}

// SaveAccess will save a token and it's access data to redis
func (r *RedisOsinStorageInterface) SaveAccess(accessData *osin.AccessData) error {
	authDataJSON, err := json.Marshal(accessData)
	if err != nil {
		return err
	}

	key := prefixAccess + accessData.AccessToken
	log.Debug("Saving ACCESS key: ", key)

	// Overide default ExpiresIn:
	if globalConf.OauthTokenExpire != 0 {
		accessData.ExpiresIn = globalConf.OauthTokenExpire
	}

	r.store.SetKey(key, string(authDataJSON), int64(accessData.ExpiresIn))

	// Create a SessionState object and register it with the authmanager
	var newSession session.SessionState

	// ------
	checkPolicy := true
	if accessData.UserData != nil {
		checkPolicy = false
		err := json.Unmarshal([]byte(accessData.UserData.(string)), &newSession)
		if err != nil {
			log.Info("Couldn't decode SessionState from UserData, checking policy: ", err)
			checkPolicy = true
		}
	}

	if checkPolicy {
		// defined in JWT middleware
		sessionFromPolicy, err := generateSessionFromPolicy(accessData.Client.GetPolicyID(), "", false)
		if err != nil {
			return errors.New("Couldn't use policy or key rules to create token, failing")
		}

		newSession = sessionFromPolicy
	}

	// ------

	// Set the client ID for analytics
	newSession.OauthClientID = accessData.Client.GetId()

	// Override timeouts so that we can be in sync with Osin
	newSession.Expires = time.Now().Unix() + int64(accessData.ExpiresIn)

	// Use the default session expiry here as this is OAuth
	r.sessionManager.UpdateSession(accessData.AccessToken, &newSession, int64(accessData.ExpiresIn))

	// Store the refresh token too
	if accessData.RefreshToken != "" {
		accessDataJSON, err := json.Marshal(accessData)
		if err != nil {
			return err
		}
		key := prefixRefresh + accessData.RefreshToken
		log.Debug("Saving REFRESH key: ", key)
		refreshExpire := int64(1209600) // 14 days
		if globalConf.OauthRefreshExpire != 0 {
			refreshExpire = globalConf.OauthRefreshExpire
		}
		r.store.SetKey(key, string(accessDataJSON), refreshExpire)
		log.Debug("STORING ACCESS DATA: ", string(accessDataJSON))
		return nil
	}

	return nil
}

// LoadAccess will load access data from redis
func (r *RedisOsinStorageInterface) LoadAccess(token string) (*osin.AccessData, error) {
	key := prefixAccess + token
	log.Debug("Loading ACCESS key: ", key)
	accessJSON, err := r.store.GetKey(key)

	if err != nil {
		log.Error("Failure retreiving access token by key: ", err)
		return nil, err
	}

	accessData := osin.AccessData{}
	accessData.Client = new(OAuthClient)
	if err := json.Unmarshal([]byte(accessJSON), &accessData); err != nil {
		log.Error("Couldn't unmarshal OAuth auth data object (LoadAccess): ", err)
		return nil, err
	}

	return &accessData, nil
}

// RemoveAccess will remove access data from Redis
func (r *RedisOsinStorageInterface) RemoveAccess(token string) error {
	key := prefixAccess + token
	r.store.DeleteKey(key)

	// remove the access token from central storage too
	r.sessionManager.RemoveSession(token)

	return nil
}

// LoadRefresh will load access data from Redis
func (r *RedisOsinStorageInterface) LoadRefresh(token string) (*osin.AccessData, error) {
	key := prefixRefresh + token
	log.Debug("Loading REFRESH key: ", key)
	accessJSON, err := r.store.GetKey(key)

	if err != nil {
		log.Error("Failure retreiving access token by key: ", err)
		return nil, err
	}

	// new interface means having to make this nested... ick.
	accessData := osin.AccessData{}
	accessData.Client = new(OAuthClient)
	if err := json.Unmarshal([]byte(accessJSON), &accessData); err != nil {
		log.Error("Couldn't unmarshal OAuth auth data object (LoadRefresh): ", err,
			"; Decoding: ", accessJSON)
		return nil, err
	}

	return &accessData, nil
}

// RemoveRefresh will remove a refresh token from redis
func (r *RedisOsinStorageInterface) RemoveRefresh(token string) error {
	key := prefixRefresh + token
	r.store.DeleteKey(key)
	return nil
}

// LoadRefresh will load access data from Redis
func (r *RedisOsinStorageInterface) GetUser(username string) (*SessionState, error) {
	key := username
	log.Debug("Loading User key: ", key)
	accessJSON, err := r.store.GetRawKey(key)

	if err != nil {
		log.Error("Failure retreiving access token by key: ", err)
		return nil, err
	}

	// new interface means having to make this nested... ick.
	sess := session.SessionState{}
	if err := json.Unmarshal([]byte(accessJSON), &sess); err != nil {
		log.Error("Couldn't unmarshal OAuth auth data object (LoadRefresh): ", err,
			"; Decoding: ", accessJSON)
		return nil, err
	}

	return &sess, nil
}

func (r *RedisOsinStorageInterface) SetUser(username string, session *SessionState, timeout int64) error {
	key := username
	authDataJSON, err := json.Marshal(session)
	if err != nil {
		return err
	}

	if err := r.store.SetRawKey(key, string(authDataJSON), timeout); err != nil {
		log.Error("Failure setting user token by key: ", err)
		return err
	}

	return nil

}

// AccessTokenGenTyk is a modified authorization token generator that uses the same method used to generate tokens for Tyk authHandler
type AccessTokenGenTyk = apispec.AccessTokenGenTyk
