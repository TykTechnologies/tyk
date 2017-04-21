package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	osin "github.com/lonelycode/osin"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
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
	ClientID          string      `json:"id"`
	ClientSecret      string      `json:"secret"`
	ClientRedirectURI string      `json:"redirecturi"`
	UserData          interface{} `json:",omitempty"`
	PolicyID          string      `json:"policyid"`
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

// OAuthHandlers are the HTTP Handlers that manage the Tyk OAuth flow
type OAuthHandlers struct {
	Manager OAuthManager
}

func (o *OAuthHandlers) generateOAuthOutputFromOsinResponse(osinResponse *osin.Response) ([]byte, bool) {

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
		return nil, false
	}
	return respData, true

}

func (o *OAuthHandlers) notifyClientOfNewOauth(notification NewOAuthNotification) bool {
	log.Info("[OAuth] Notifying client host")
	go o.Manager.API.NotificationsDetails.SendRequest(false, 0, notification)
	return true
}

// HandleGenerateAuthCodeData handles a resource provider approving an OAuth request from a client
func (o *OAuthHandlers) HandleGenerateAuthCodeData(w http.ResponseWriter, r *http.Request) {
	var responseMessage []byte
	var code int

	if r.Method == "POST" {
		// On AUTH grab session state data and add to UserData (not validated, not good!)
		sessionStateJSONData := r.FormValue("key_rules")
		if sessionStateJSONData == "" {
			log.Warning("Authorise request is missing key_rules in params, policy will be required!")
		}

		// Handle the authorisation and write the JSON output to the resource provider
		resp := o.Manager.HandleAuthorisation(r, true, sessionStateJSONData)
		code = 200
		responseMessage, _ = o.generateOAuthOutputFromOsinResponse(resp)
		if resp.IsError {
			code = resp.ErrorStatusCode
			log.Error("[OAuth] OAuth response marked as error: ", resp)
		}

	} else {
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	w.Write(responseMessage)
}

// HandleAuthorizePassthrough handles a Client Auth request, first it checks if the client
// is OK (otherwise it blocks the request), then it forwards on to the resource providers approval URI
func (o *OAuthHandlers) HandleAuthorizePassthrough(w http.ResponseWriter, r *http.Request) {
	var responseMessage []byte
	var code int

	if r.Method == "GET" || r.Method == "POST" {
		// Extract client data and check
		resp := o.Manager.HandleAuthorisation(r, false, "")
		if resp.IsError {
			log.Error("There was an error with the request: ", resp)
			// Something went wrong, write out the error details and kill the response
			w.WriteHeader(resp.ErrorStatusCode)
			responseMessage = createError(resp.StatusText)
			w.Write(responseMessage)
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
	} else {
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
		w.WriteHeader(code)
		w.Write(responseMessage)
	}

}

// HandleAccessRequest handles the OAuth 2.0 token or refresh access request, and wraps Tyk's own and Osin's OAuth handlers,
// returns a response to the client and notifies the provider of the access request (in order to track identity against
// OAuth tokens without revealing tokens before they are requested).
func (o *OAuthHandlers) HandleAccessRequest(w http.ResponseWriter, r *http.Request) {
	var responseMessage []byte
	var code int

	if r.Method == "GET" || r.Method == "POST" {
		// Handle response
		resp := o.Manager.HandleAccess(r)
		responseMessage, _ = o.generateOAuthOutputFromOsinResponse(resp)
		if resp.IsError {
			// Something went wrong, write out the error details and kill the response
			w.WriteHeader(resp.ErrorStatusCode)
			w.Write(responseMessage)
			return
		}

		// Ping endpoint with o_auth key and auth_key
		code = 200
		code := r.FormValue("code")
		oldRefreshToken := r.FormValue("refresh_token")
		log.Debug("AUTH CODE: ", code)
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
			AuthCode:         code,
			NewOAuthToken:    newOauthToken,
			RefreshToken:     refreshToken,
			OldRefreshToken:  oldRefreshToken,
			NotificationType: notificationType,
		}

		o.notifyClientOfNewOauth(newNotification)

	} else {
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
	}

	w.WriteHeader(code)
	w.Write(responseMessage)
}

// OAuthManager handles and wraps osin OAuth2 functions to handle authorise and access requests
type OAuthManager struct {
	API        *APISpec
	OsinServer *TykOsinServer
}

// HandleAuthorisation creates the authorisation data for the request
func (o *OAuthManager) HandleAuthorisation(r *http.Request, complete bool, sessionState string) *osin.Response {
	resp := o.OsinServer.NewResponse()

	if ar := o.OsinServer.HandleAuthorizeRequest(resp, r); ar != nil {
		// Since this is called by the Reource provider (proxied API), we assume it has been approved
		ar.Authorized = true

		if complete {
			ar.UserData = sessionState
			o.OsinServer.FinishAuthorizeRequest(resp, r, ar)
		}
	}
	if resp.IsError && resp.InternalError != nil {
		log.Error(resp.InternalError)
	}

	return resp
}

// HandleAccess wraps an access request with osin's primitives
func (o *OAuthManager) HandleAccess(r *http.Request) *osin.Response {
	resp := o.OsinServer.NewResponse()
	var sessionState *SessionState
	var username string
	if ar := o.OsinServer.HandleAccessRequest(resp, r); ar != nil {

		if ar.Type == osin.PASSWORD {
			username = r.Form.Get("username")
			password := r.Form.Get("password")
			keyName := o.API.OrgID + username
			if config.HashKeys {
				// HASHING? FIX THE KEY
				keyName = doHash(keyName)
			}
			searchKey := "apikey-" + keyName
			log.Debug("Getting: ", searchKey)

			var err error
			sessionState, err = o.OsinServer.Storage.GetUser(searchKey)
			if err != nil {
				log.Warning("Attempted access with non-existent user (OAuth password flow).")
			} else {
				var passMatch bool
				if sessionState.BasicAuthData.Hash == HashBCrypt {
					err := bcrypt.CompareHashAndPassword([]byte(sessionState.BasicAuthData.Password), []byte(password))

					if err == nil {
						passMatch = true
					}
				}

				if sessionState.BasicAuthData.Hash == HashPlainText {
					if sessionState.BasicAuthData.Password == password {
						passMatch = true
					}
				}

				if passMatch {
					log.Info("Here we are")
					ar.Authorized = true
					// not ideal, but we need to copy the session state across
					pw := sessionState.BasicAuthData.Password
					hs := sessionState.BasicAuthData.Hash

					sessionState.BasicAuthData.Password = ""
					sessionState.BasicAuthData.Hash = ""
					asString, _ := json.Marshal(sessionState)
					ar.UserData = string(asString)

					sessionState.BasicAuthData.Password = pw
					sessionState.BasicAuthData.Hash = hs

					//log.Warning("Old Keys: ", sessionState.OauthKeys)
				}
			}
		} else {
			// Using a manual flow
			ar.Authorized = true
		}

		// Does the user have an old OAuth token for this client?
		if sessionState != nil {
			if sessionState.OauthKeys != nil {
				log.Debug("There's keys here bill...")
				oldToken, foundKey := sessionState.OauthKeys[ar.Client.GetId()]
				if foundKey {
					log.Info("Found old token, revoking: ", oldToken)

					o.API.SessionManager.RemoveSession(oldToken)
				}
			}
		}

		log.Debug("[OAuth] Finishing access request ")
		o.OsinServer.FinishAccessRequest(resp, r, ar)

		new_token, foundNewToken := resp.Output["access_token"]
		if username != "" {
			if foundNewToken {
				log.Debug("Updating token data in key")
				if sessionState.OauthKeys == nil {
					sessionState.OauthKeys = make(map[string]string)
				}
				sessionState.OauthKeys[ar.Client.GetId()] = new_token.(string)
				log.Debug("New token: ", new_token.(string))
				log.Debug("Keys: ", sessionState.OauthKeys)

				keyName := o.API.OrgID + username

				log.Debug("Updating user:", keyName)
				err := o.API.SessionManager.UpdateSession(keyName, *sessionState, GetLifetime(o.API, sessionState))
				if err != nil {
					log.Error(err)
				}
			}
		}

	}
	if resp.IsError && resp.InternalError != nil {
		log.Error("ERROR: ", resp.InternalError)
	}

	return resp
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

type ExtendedOsinStorageInterface interface {
	// Create OAuth clients
	SetClient(id string, client osin.Client, ignorePrefix bool) error

	// Custom getter to handle prefixing issues in Redis
	GetClientNoPrefix(id string) (osin.Client, error)

	GetClients(filter string, ignorePrefix bool) ([]osin.Client, error)

	DeleteClient(id string, ignorePrefix bool) error

	// Clone the storage if needed. For example, using mgo, you can clone the session with session.Clone
	// to avoid concurrent access problems.
	// This is to avoid cloning the connection at each method access.
	// Can return itself if not a problem.
	Clone() osin.Storage

	// Close the resources the Storate potentially holds (using Clone for example)
	Close()

	// GetClient loads the client by id (client_id)
	GetClient(id string) (osin.Client, error)

	// SaveAuthorize saves authorize data.
	SaveAuthorize(*osin.AuthorizeData) error

	// LoadAuthorize looks up AuthorizeData by a code.
	// Client information MUST be loaded together.
	// Optionally can return error if expired.
	LoadAuthorize(code string) (*osin.AuthorizeData, error)

	// RemoveAuthorize revokes or deletes the authorization code.
	RemoveAuthorize(code string) error

	// SaveAccess writes AccessData.
	// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
	SaveAccess(*osin.AccessData) error

	// LoadAccess retrieves access data by token. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadAccess(token string) (*osin.AccessData, error)

	// RemoveAccess revokes or deletes an AccessData.
	RemoveAccess(token string) error

	// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadRefresh(token string) (*osin.AccessData, error)

	// RemoveRefresh revokes or deletes refresh AccessData.
	RemoveRefresh(token string) error

	// GetUser retrieves a Basic Access user token type from the key store
	GetUser(string) (*SessionState, error)

	// SetUser updates a Basic Access user token type in the key store
	SetUser(string, *SessionState, int64) error
}

// TykOsinServer subclasses osin.Server so we can add the SetClient method without wrecking the lbrary
type TykOsinServer struct {
	osin.Server
	Config            *osin.ServerConfig
	Storage           ExtendedOsinStorageInterface
	AuthorizeTokenGen osin.AuthorizeTokenGen
	AccessTokenGen    osin.AccessTokenGen
}

// TykOsinNewServer creates a new server instance, but uses an extended interface so we can SetClient() too.
func TykOsinNewServer(config *osin.ServerConfig, storage ExtendedOsinStorageInterface) *TykOsinServer {

	overrideServer := TykOsinServer{
		Config:            config,
		Storage:           storage,
		AuthorizeTokenGen: &osin.AuthorizeTokenGenDefault{},
		AccessTokenGen:    &AccessTokenGenTyk{},
	}

	overrideServer.Server.Config = config
	overrideServer.Server.Storage = storage
	overrideServer.Server.AuthorizeTokenGen = overrideServer.AuthorizeTokenGen
	overrideServer.Server.AccessTokenGen = &AccessTokenGenTyk{}

	return &overrideServer
}

// TODO: Refactor this to move prefix handling into a checker method, then it can be an unexported setting in the struct.
// RedisOsinStorageInterface implements osin.Storage interface to use Tyk's own storage mechanism
type RedisOsinStorageInterface struct {
	store          StorageHandler
	sessionManager SessionHandler
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
	if !config.Storage.EnableCluster {
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
			return theseClients, err
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
	if config.OauthTokenExpire != 0 {
		accessData.ExpiresIn = config.OauthTokenExpire
	}

	r.store.SetKey(key, string(authDataJSON), int64(accessData.ExpiresIn))

	// Create a SessionState object and register it with the authmanager
	var newSession SessionState

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
	r.sessionManager.UpdateSession(accessData.AccessToken, newSession, int64(accessData.ExpiresIn))

	// Store the refresh token too
	if accessData.RefreshToken != "" {
		accessDataJSON, err := json.Marshal(accessData)
		if err != nil {
			return err
		}
		key := prefixRefresh + accessData.RefreshToken
		log.Debug("Saving REFRESH key: ", key)
		refreshExpire := int64(1209600) // 14 days
		if config.OauthRefreshExpire != 0 {
			refreshExpire = config.OauthRefreshExpire
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

// AccessTokenGenTyk is a modified authorization token generator that uses the same method used to generate tokens for Tyk authHandler
type AccessTokenGenTyk struct{}

// GenerateAccessToken generates base64-encoded UUID access and refresh tokens
func (a *AccessTokenGenTyk) GenerateAccessToken(data *osin.AccessData, generaterefresh bool) (accesstoken, refreshtoken string, err error) {
	log.Info("[OAuth] Generating new token")

	var newSession SessionState
	checkPolicy := true
	if data.UserData != nil {
		checkPolicy = false
		err := json.Unmarshal([]byte(data.UserData.(string)), &newSession)
		if err != nil {
			log.Info("[GenerateAccessToken] Couldn't decode SessionState from UserData, checking policy: ", err)
			checkPolicy = true
		}
	}

	if checkPolicy {
		// defined in JWT middleware
		sessionFromPolicy, err := generateSessionFromPolicy(data.Client.GetPolicyID(), "", false)
		if err != nil {
			return "", "", errors.New("Couldn't use policy or key rules to create token, failing")
		}

		newSession = sessionFromPolicy
	}

	accesstoken = keyGen.GenerateAuthKey(newSession.OrgID)

	if generaterefresh {
		u6 := uuid.NewV4()
		refreshtoken = base64.StdEncoding.EncodeToString([]byte(u6.String()))
	}
	return
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
	session := SessionState{}
	if err := json.Unmarshal([]byte(accessJSON), &session); err != nil {
		log.Error("Couldn't unmarshal OAuth auth data object (LoadRefresh): ", err,
			"; Decoding: ", accessJSON)
		return nil, err
	}

	return &session, nil
}

func (r *RedisOsinStorageInterface) SetUser(username string, sessionState *SessionState, timeout int64) error {
	key := username
	authDataJSON, err := json.Marshal(sessionState)
	if err != nil {
		return err
	}

	if err := r.store.SetRawKey(key, string(authDataJSON), timeout); err != nil {
		log.Error("Failure setting user token by key: ", err)
		return err
	}

	return nil

}
