package main

import (
	"net/http"
	"github.com/RangelReale/osin"
	"fmt"
	"encoding/json"
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
	ClientID string
	ClientSecret string
	ClientRedirectURI string
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
	OldOAuthToken string
	RefreshToken string
	NotificationType OAuthNotificationType
}

// OAuthHandlers are the HTTP Handlers that manage the Tyk OAuth flow
type OAuthHandlers struct{
	Manager OAuthManager
}

func (o *OAuthHandlers) generateOAuthOutputFromOsinResponse(osinResponse *osin.Response) ([]byte, bool) {
	if respData, marshalErr := json.Marshal(&osinResponse.Output); marshalErr != nil {
		return respData, true
	}
	return []byte{}, false
}


func (o *OAuthHandlers) notifyClientOfNewOauth(notification NewOAuthNotification) bool {
	log.Warning("MOCK NOTIFICATION: NEW AUTH")
	log.Warning("Output: ", notification)
	return true
}

// GenerateAuthCodeData handles a resource provider approving an OAuth request from a client
func (o *OAuthHandlers) HandleGenerateAuthCodeData(w http.ResponseWriter, r *http.Request) {
	var responseMessage []byte
	var code int

	if r.Method == "GET" {
		// Handle the authorisation and write the JSON output to the resource provider
		resp := o.Manager.HandleAuthorisation(r)
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
		resp := o.Manager.HandleAuthorisation(r)
		responseMessage, _ = o.generateOAuthOutputFromOsinResponse(resp)
		if resp.IsError {
			// Something went wrong, write out the error details and kill the response
			w.WriteHeader(resp.ErrorStatusCode)
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

		// TODO: This isn;t working
		newNotification := NewOAuthNotification{
			AuthCode: resp.Output["code"].(string),
			NewOAuthToken: resp.Output["access_token"].(string),
			RefreshToken: resp.Output["refresh_token"].(string),
			NotificationType: NEW_ACCESS_TOKEN,
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
	OsinServer *osin.Server
}

// HandleAuthorisation creates the authorisation data for the request
func (o *OAuthManager) HandleAuthorisation(r *http.Request) *osin.Response {
	resp := o.OsinServer.NewResponse()
	if ar := o.OsinServer.HandleAuthorizeRequest(resp, r); ar != nil {
		// Since this is called by the Reource provider (proxied API), we assume it has been approved
		ar.Authorized = true
		o.OsinServer.FinishAuthorizeRequest(resp, r, ar)
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
	AUTH_PREFIX string = "oauth-authorize-"
	CLIENT_PREFIX string = "oauth-clientid-"
	ACCESS_PREFIX string = "oauth-access-"
	REFRESH_PREFIX string = "oauth-refresh-"
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

// SetClient creates client data
func (r RedisOsinStorageInterface) SetClient(id string, client *osin.Client) error {

	if clientDataJSON, marshalErr := json.Marshal(&client); marshalErr != nil {
		key := CLIENT_PREFIX + id
		r.store.SetKey(key, string(clientDataJSON), 0)
		return nil
	} else {
		return marshalErr
	}
}

// SaveAuthorize saves authorisation data to REdis
func (r RedisOsinStorageInterface) SaveAuthorize(authData *osin.AuthorizeData) error{

	if authDataJSON, marshalErr := json.Marshal(&authData); marshalErr != nil {
		key := AUTH_PREFIX + authData.Code
		r.store.SetKey(key, string(authDataJSON), int64(authData.ExpiresIn))
		return nil
	} else {
		return marshalErr
	}
}

// LoadAuthorize loads auth data from redis
func (r RedisOsinStorageInterface) LoadAuthorize(code string) (*osin.AuthorizeData, error){
	key := AUTH_PREFIX + code
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
		key := ACCESS_PREFIX + accessData.AccessToken
		r.store.SetKey(key, string(authDataJSON), int64(accessData.ExpiresIn))
		return nil
	} else {
		return marshalErr
	}

	// Store the refresh token too
	if accessData.RefreshToken != "" {
		if authDataJSON, marshalErr := json.Marshal(&accessData); marshalErr != nil {
			key := REFRESH_PREFIX + accessData.RefreshToken
			r.store.SetKey(key, string(authDataJSON), int64(accessData.ExpiresIn))
			return nil
		} else {
			return marshalErr
		}
	}

	return nil
}

// LoadAccess will load access data from redis
func (r RedisOsinStorageInterface) LoadAccess(token string) (*osin.AccessData, error){
	key := ACCESS_PREFIX + token
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
	return nil
}

// LoadRefresh will load access data from Redis
func (r RedisOsinStorageInterface) LoadRefresh(token string) (*osin.AccessData, error){
	key := REFRESH_PREFIX + token
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

