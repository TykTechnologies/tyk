package main

import (
	"net/http"
	"github.com/RangelReale/osin"
	"fmt"
	"encoding/json"
	"encoding/base64"
	"github.com/nu7hatch/gouuid"
	"strings"
	"time"
)
/*
TODO:
1. Need to store OAuth client app registrations:
	- Client ID
	- Client Secret
	- Client redirect URI

2. Need to provide generic endpoints for Proxy API's to integrate with:
	a. {{api_id}}/oauth/authorize -> Called after login on API provider integration page, returns JSON
	   of auth_code, oauth_token and redirect URI for the provider to send the user to (client redirect URI)
	b. {{api-_id}}/oauth/{{oauth_token}} -> Returns key data (same as other key retrieval, just managed)

3. Need to provide generic access endpoints for Client systems to work with:
	a. {{api_id}}/oauth/token -> Called by client app with auth_code to retrieve oauth_token and refresh_token

4. Update the Api Definition object to include an UseOauth2 flag - this will force auth_header retrieval to use the correct
   header name. This will need to b different as we will only support Bearer codes.
   	a. OAuth needs a few extra options if enabled:
   		1. Add a RefreshNotifyHook string to notify resource of refreshed keys
   		2. EnableRefreshTokens -> Basically disallows auth_code requests
   		3. Authentication URL -> URL to redirect the user to

5. Requires a webhook handler to notify resource provider when an oauth token is updated through refresh (POSTs old_oauth_token,
   new_oauth_token - will do so until it receives a 200 OK response or max 3 times).

IDea:
-----
1. Request to /authorize
2. Tyk extracts all relevant data and pre-screens client_id, client_secret and redirect_uri
3. Instead of proxying the request it redirects the user to the login page on the resource
4. Resource presents approve / deny window to user
5. If approve is clicked, resource pings oauth/authorise which is the actual authorize endpoint (requires admin key),
   this returns oauth details to resource as well as redirect URI
6. User is redirected to redirect URI with auth_code
7. Client API makes all calls with bearer token

Effort required by Resource Owner:
1. Create a login & approve/deny page
2. Send an API request to Tyk to generate an auth_code
3. Create endpoint to accept key change notifications

*/

// OAuthClient is a representation within an APISpec of a client
type OAuthClient struct {
	ClientID string			`json:"client_id"`
	ClientSecret string		`json:"secret"`
	ClientRedirectURI string	`json:"redirect_uri"`
}

type OAuthNotificationType string
const (
	NEW_ACCESS_TOKEN OAuthNotificationType = "new"
	REFRESH_ACCESS_TOKEN OAuthNotificationType = "refresh"
	NEW_AUTH_TOKEN OAuthNotificationType = "pending"
)

type NewOAuthNotification struct {
	AuthCode string
	NewOAuthToken string
	RefreshToken string
	OldRefreshToken string
	NotificationType OAuthNotificationType
}

// OAuthHandlers are the HTTP Handlers that manage the Tyk OAuth flow
type OAuthHandlers struct{
	Manager OAuthManager
}

func (o *OAuthHandlers) generateOAuthOutputFromOsinResponse(osinResponse *osin.Response) ([]byte, bool) {

	// TODO: Might need to clear this out
	if osinResponse.Output["state"] == "" {
		log.Debug("Removing state")
		delete(osinResponse.Output, "state")
	}

	redirect, rediErr := osinResponse.GetRedirectUrl()

	if rediErr == nil {
		// Hack to inject redirect into response
		osinResponse.Output["redirect_to"] = redirect
	}

	if respData, marshalErr := json.Marshal(&osinResponse.Output); marshalErr != nil {
		return []byte{}, false
	} else {
		return respData, true
	}
}


func (o *OAuthHandlers) notifyClientOfNewOauth(notification NewOAuthNotification) bool {
	log.Info("Notifying client host")
	go o.Manager.Api.NotificationsDetails.SendRequest(false, 0, notification)
	return true
}

// GenerateAuthCodeData handles a resource provider approving an OAuth request from a client
func (o *OAuthHandlers) HandleGenerateAuthCodeData(w http.ResponseWriter, r *http.Request) {
	var responseMessage []byte
	var code int

	if r.Method == "POST" {
		// On AUTH grab session state data and add to UserData (not validated, not good!)
		sessionStateJSONData := r.FormValue("key_rules")
		if sessionStateJSONData == "" {
			responseMessage := createError("Authorise request is missing key_rules in params")
			w.WriteHeader(400)
			fmt.Fprintf(w, string(responseMessage))
			return
		}

		// Handle the authorisation and write the JSON output to the resource provider
		resp := o.Manager.HandleAuthorisation(r, true, sessionStateJSONData)
		code = 200
		responseMessage, _ = o.generateOAuthOutputFromOsinResponse(resp)
		if resp.IsError {
			code = resp.ErrorStatusCode
			log.Error("OAuth response marked as error")
			log.Error(resp)
		}

	} else {
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
	}


	w.WriteHeader(code)
	fmt.Fprintf(w, string(responseMessage))
}

// AuthorizePassthrough handles a Client Auth request, first it checks if the client
// is OK (otherwise it blocks the request), then it forwards on to the resource providers approval URI
func (o *OAuthHandlers) HandleAuthorizePassthrough(w http.ResponseWriter, r *http.Request) {
	var responseMessage []byte
	var code int

	if r.Method == "GET" || r.Method == "POST" {
		// Extract client data and check
		resp := o.Manager.HandleAuthorisation(r, false, "")
		responseMessage, _ = o.generateOAuthOutputFromOsinResponse(resp)
		if resp.IsError {
			// Something went wrong, write out the error details and kill the response
			w.WriteHeader(resp.ErrorStatusCode)
			responseMessage = createError(resp.StatusText)
			fmt.Fprintf(w, string(responseMessage))
			return
		}

		// TODO: Redirect to our client login page
		log.Warning("At this point I should redirect if everything is valid")


	} else {
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
	}

	w.WriteHeader(code)
	fmt.Fprintf(w, string(responseMessage))
}

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
			fmt.Fprintf(w, string(responseMessage))
			return
		}

		// Ping endpoint with o_auth key and auth_key
		code = 200
		code := r.FormValue("code")
		OldRefreshToken := r.FormValue("refresh_token")
		log.Debug("AUTH CODE: ", code)
		NewOAuthToken := ""
		if resp.Output["access_token"] != nil {
			NewOAuthToken = resp.Output["access_token"].(string)
		}
		log.Debug("TOKEN: ", NewOAuthToken)
		RefreshToken := ""
		if resp.Output["refresh_token"] != nil {
			RefreshToken = resp.Output["refresh_token"].(string)
		}
		log.Debug("REFRESH: ", RefreshToken)
		log.Debug("Old REFRESH: ", OldRefreshToken)

		notificationType := NEW_ACCESS_TOKEN
		if OldRefreshToken != "" {
			notificationType = REFRESH_ACCESS_TOKEN
		}

		newNotification := NewOAuthNotification{
			AuthCode: code,
			NewOAuthToken: NewOAuthToken,
			RefreshToken: RefreshToken,
			OldRefreshToken: OldRefreshToken,
			NotificationType: notificationType,
		}

		o.notifyClientOfNewOauth(newNotification)


	} else {
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
	}

	w.WriteHeader(code)
	fmt.Fprintf(w, string(responseMessage))
}

// OAuthManager handles and wraps osin OAuth2 functions to handle authorise and access requests
type OAuthManager struct {
	Api APISpec
	OsinServer *osin.Server
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
		fmt.Printf("ERROR: %s\n", resp.InternalError)
	}

	return resp
}

// HandleAccess wraps an access request with osin's primitives
func (o *OAuthManager) HandleAccess(r *http.Request) *osin.Response {
	resp := o.OsinServer.NewResponse()
	if ar := o.OsinServer.HandleAccessRequest(resp, r); ar != nil {
		ar.Authorized = true
		o.OsinServer.FinishAccessRequest(resp, r, ar)
	}
	if resp.IsError && resp.InternalError != nil {
		log.Error("ERROR: ", resp.InternalError)
	}

	return resp
}

// IsRequestValid will check if a key is valid or not
func (o *OAuthManager) IsRequestValid(r *http.Request) bool {
	// TODO: Integrate this
	return true
}

// These enums fix the prefix to use when storing various OAuth keys and data, since we
// delegate everything to the osin framework
const (
	AUTH_PREFIX string = "oauth-authorize."
	CLIENT_PREFIX string = "oauth-clientid."
	ACCESS_PREFIX string = "oauth-access."
	REFRESH_PREFIX string = "oauth-refresh."
)

// RedisOsinStorageInterface implements osin.Storage interface to use Tyk's own storage mechanism
type RedisOsinStorageInterface struct{
	store StorageHandler
}

// GetClient will retrieve client data
func (r RedisOsinStorageInterface) GetClient(id string) (*osin.Client, error){
	key := CLIENT_PREFIX + id

	clientJSON, storeErr := r.store.GetKey(key)

	if storeErr != nil {
		log.Error("Failure retreiving client ID key")
		log.Error(storeErr)
		return nil, storeErr
	}

	thisClient := osin.Client{}
	if marshalErr := json.Unmarshal([]byte(clientJSON), &thisClient); marshalErr != nil {
		log.Error("Couldn't unmarshal OAuth client object")
		log.Error(marshalErr)
	}

	return &thisClient, nil
}

// GetClient will retrieve client data
func (r RedisOsinStorageInterface) GetClientNoPrefix(id string) (*osin.Client, error){

	key := id

	clientJSON, storeErr := r.store.GetKey(key)

	if storeErr != nil {
		log.Error("Failure retreiving client ID key")
		log.Error(storeErr)
		return nil, storeErr
	}

	thisClient := osin.Client{}
	if marshalErr := json.Unmarshal([]byte(clientJSON), &thisClient); marshalErr != nil {
		log.Error("Couldn't unmarshal OAuth client object")
		log.Error(marshalErr)
	}

	return &thisClient, nil
}

func (r RedisOsinStorageInterface) GetClients(filter string, ignorePrefix bool) (*[]osin.Client, error){
	key := CLIENT_PREFIX + filter
	if ignorePrefix {
		key = filter
	}

	clientJSON := r.store.GetKeysAndValuesWithFilter(key)

	theseClients := []osin.Client{}

	for _, clientJSON := range(clientJSON) {
		thisClient := osin.Client{}
		if marshalErr := json.Unmarshal([]byte(clientJSON), &thisClient); marshalErr != nil {
			log.Error("Couldn't unmarshal OAuth client object")
			log.Error(marshalErr)
			return &theseClients, marshalErr
		}
		theseClients = append(theseClients, thisClient)
	}

	return &theseClients, nil
}

// SetClient creates client data
func (r RedisOsinStorageInterface) SetClient(id string, client *osin.Client, ignorePrefix bool) error {
	clientDataJSON, err := json.Marshal(client)

	if err != nil {
		log.Error("Couldn't marshal client data")
		log.Error(err)
		return err
	}

	key := CLIENT_PREFIX + id
	if ignorePrefix {
		key = id
	}

	r.store.SetKey(key, string(clientDataJSON), 0)
	return nil
}

// DeleteClient Removes a client from the system
func (r RedisOsinStorageInterface) DeleteClient(id string, ignorePrefix bool) error {
	key := CLIENT_PREFIX + id
	if ignorePrefix {
		key = id
	}

	r.store.DeleteKey(key)
	return nil
}

// SaveAuthorize saves authorisation data to REdis
func (r RedisOsinStorageInterface) SaveAuthorize(authData *osin.AuthorizeData) error{
	if authDataJSON, marshalErr := json.Marshal(&authData); marshalErr != nil {
		return marshalErr
	} else {
		key := AUTH_PREFIX + authData.Code
		log.Debug("Saving auth code: ", key)
		r.store.SetKey(key, string(authDataJSON), int64(authData.ExpiresIn))
		return nil

	}
}

// LoadAuthorize loads auth data from redis
func (r RedisOsinStorageInterface) LoadAuthorize(code string) (*osin.AuthorizeData, error){
	key := AUTH_PREFIX + code
	log.Debug("Loading auth code: ", key)
	authJSON, storeErr := r.store.GetKey(key)

	if storeErr != nil {
		log.Error("Failure retreiving auth code key")
		log.Error(storeErr)
		return nil, storeErr
	}

	thisAuthData := osin.AuthorizeData{}
	if marshalErr := json.Unmarshal([]byte(authJSON), &thisAuthData); marshalErr != nil {
		log.Error("Couldn't unmarshal OAuth auth data object")
		log.Error(marshalErr)
		return nil, marshalErr
	}

	return &thisAuthData, nil
}

// RemoveAuthorize removes authorisation keys from redis
func (r RedisOsinStorageInterface) RemoveAuthorize(code string) error{
	key := AUTH_PREFIX + code
	r.store.DeleteKey(key)
	return nil
}

// SaveAccess will save a token and it's access data to redis
func (r RedisOsinStorageInterface) SaveAccess(accessData *osin.AccessData) error{

	if authDataJSON, marshalErr := json.Marshal(accessData); marshalErr != nil {
		return marshalErr
	} else {
		key := ACCESS_PREFIX + accessData.AccessToken
		log.Debug("Saving ACCESS key: ", key)
		r.store.SetKey(key, string(authDataJSON), int64(accessData.ExpiresIn))

		// Create a SessionState object and register it with the authmanager
		var newSession SessionState
		marshalErr := json.Unmarshal([]byte(accessData.UserData.(string)), &newSession)

		if marshalErr != nil {
			log.Error("Couldn't decode SessionState from UserData")
			log.Error(marshalErr)
			return marshalErr
		}

		// Override timeouts so that we can be in sync with Osin
		newSession.Expires = time.Now().Unix() + int64(accessData.ExpiresIn)

		authManager.UpdateSession(accessData.AccessToken, newSession)

	}

	// Store the refresh token too
	if accessData.RefreshToken != "" {
		if authDataJSON, marshalErr := json.Marshal(&accessData); marshalErr != nil {
			return marshalErr
		} else {
			key := REFRESH_PREFIX + accessData.RefreshToken
			log.Debug("Saving REFRESH key: ", key)
			r.store.SetKey(key, string(authDataJSON), int64(accessData.ExpiresIn))
			return nil

		}
	}

	return nil
}

// LoadAccess will load access data from redis
func (r RedisOsinStorageInterface) LoadAccess(token string) (*osin.AccessData, error){
	key := ACCESS_PREFIX + token
	log.Debug("Loading ACCESS key: ", key)
	accessJSON, storeErr := r.store.GetKey(key)

	if storeErr != nil {
		log.Error("Failure retreiving access token by key")
		log.Error(storeErr)
		return nil, storeErr
	}

	thisAccessData := osin.AccessData{}
	if marshalErr := json.Unmarshal([]byte(accessJSON), &thisAccessData); marshalErr != nil {
		log.Error("Couldn't unmarshal OAuth auth data object")
		log.Error(marshalErr)
		return nil, marshalErr
	}

	return &thisAccessData, nil
}

// RemoveAccess will remove access data from Redis
func (r RedisOsinStorageInterface) RemoveAccess(token string) error{
	key := ACCESS_PREFIX + token
	r.store.DeleteKey(key)

	// remove the access token from central storage too
	authDeleted := authManager.Store.DeleteKey(token)
	if !authDeleted {
		log.Error("Couldn't remove from authManager!")
	}
	return nil
}

// LoadRefresh will load access data from Redis
func (r RedisOsinStorageInterface) LoadRefresh(token string) (*osin.AccessData, error){
	key := REFRESH_PREFIX + token
	log.Debug("Loading REFRESH key: ", key)
	accessJSON, storeErr := r.store.GetKey(key)

	if storeErr != nil {
		log.Error("Failure retreiving access token by key")
		log.Error(storeErr)
		return nil, storeErr
	}

	thisAccessData := osin.AccessData{}
	if marshalErr := json.Unmarshal([]byte(accessJSON), &thisAccessData); marshalErr != nil {
		log.Error("Couldn't unmarshal OAuth auth data object")
		log.Error(marshalErr)
		return nil, marshalErr
	}

	return &thisAccessData, nil
}

// RemoveRefresh will remove a refresh token from redis
func (r RedisOsinStorageInterface) RemoveRefresh(token string) error{
	key := REFRESH_PREFIX + token
	r.store.DeleteKey(key)
	return nil
}

// AccessTokenGenDefault is the default authorization token generator
type AccessTokenGenTyk struct {
}

// GenerateAccessToken generates base64-encoded UUID access and refresh tokens
func (a *AccessTokenGenTyk) GenerateAccessToken(data *osin.AccessData, generaterefresh bool) (accesstoken string, refreshtoken string, err error) {
	log.Info("Generating new token")
	u5, err := uuid.NewV4()
	var newSession SessionState
	marshalErr := json.Unmarshal([]byte(data.UserData.(string)), &newSession)

	if marshalErr != nil {
		log.Error("Couldn't decode SessionState from UserData")
		log.Error(marshalErr)
		return "", "", marshalErr
	}

	cleanSting := strings.Replace(u5.String(), "-", "", -1)
	accesstoken = expandKey(newSession.OrgID, cleanSting)

	if generaterefresh {
		u6, _ := uuid.NewV4()
		refreshtoken = strings.Replace(u6.String(), "-", "", -1)
		refreshtoken = base64.StdEncoding.EncodeToString([]byte(refreshtoken))
	}
	return
}
