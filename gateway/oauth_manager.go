package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/request"

	"github.com/lonelycode/osin"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"

	"strconv"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
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
	MetaData          interface{} `json:"meta_data,omitempty"`
	PolicyID          string      `json:"policyid"`
	Description       string      `json:"description"`
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
	return oc.MetaData
}

func (oc *OAuthClient) GetPolicyID() string {
	return oc.PolicyID
}

func (oc *OAuthClient) GetDescription() string {
	return oc.Description
}

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

	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err = encoder.Encode(&osinResponse.Output)
	if err != nil {
		return nil
	}
	return buffer.Bytes()
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

const (
	accessToken  = "access_token"
	refreshToken = "refresh_token"
)

//in compliance with https://tools.ietf.org/html/rfc7009#section-2.1
//ToDo: set an authentication mechanism
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

func RevokeToken(storage ExtendedOsinStorageInterface, token, tokenTypeHint string) {
	switch tokenTypeHint {
	case accessToken:
		storage.RemoveAccess(token)
	case refreshToken:
		storage.RemoveRefresh(token)
	default:
		storage.RemoveAccess(token)
		storage.RemoveRefresh(token)
	}
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

func RevokeAllTokens(storage ExtendedOsinStorageInterface, clientId, clientSecret string) (int, []string, error) {
	resp := []string{}
	client, err := storage.GetClient(clientId)
	log.Debug("Revoke all tokens")
	if err != nil {
		return http.StatusNotFound, resp, errors.New("error getting oauth client")
	}

	if client.GetSecret() != clientSecret {
		return http.StatusUnauthorized, resp, errors.New(oauthClientSecretWrong)
	}

	clientTokens, err := storage.GetClientTokens(clientId)
	if err != nil {
		return http.StatusBadRequest, resp, errors.New("cannot retrieve client tokens")
	}

	log.Debug("Tokens found to be revoked:", len(clientTokens))
	for _, token := range clientTokens {
		access, err := storage.LoadAccess(token.Token)
		if err == nil {
			resp = append(resp, access.AccessToken)
			storage.RemoveAccess(access.AccessToken)
			storage.RemoveRefresh(access.RefreshToken)
		} else {
			log.Debug("error loading access:", err.Error())
		}
	}

	return http.StatusOK, resp, nil
}

// OAuthManager handles and wraps osin OAuth2 functions to handle authorise and access requests
type OAuthManager struct {
	API        *APISpec
	OsinServer *TykOsinServer
	Gw         *Gateway `json:"-"`
}

// HandleAuthorisation creates the authorisation data for the request
func (o *OAuthManager) HandleAuthorisation(r *http.Request, complete bool, session string) *osin.Response {
	resp := o.OsinServer.NewResponse()

	if ar := o.OsinServer.HandleAuthorizeRequest(resp, r); ar != nil {
		// Since this is called by the Reource provider (proxied API), we assume it has been approved
		ar.Authorized = true

		if complete {
			ar.UserData = session
			o.OsinServer.FinishAuthorizeRequest(resp, r, ar)
		}
	}
	if resp.IsError && resp.InternalError != nil {
		log.Error(resp.InternalError)
	}

	return resp
}

// JSONToFormValues if r has header Content-Type set to application/json this
// will decode request body as json to map[string]string and adds the key/value
// pairs in r.Form.
func JSONToFormValues(r *http.Request) error {
	if r.Header.Get("Content-Type") == "application/json" {
		var o map[string]string
		err := json.NewDecoder(r.Body).Decode(&o)
		if err != nil {
			return err
		}
		if len(o) > 0 {
			if r.Form == nil {
				r.Form = make(url.Values)
			}
			for k, v := range o {
				r.Form.Set(k, v)
			}
		}

	}
	return nil
}

// HandleAccess wraps an access request with osin's primitives
func (o *OAuthManager) HandleAccess(r *http.Request) *osin.Response {
	resp := o.OsinServer.NewResponse()
	// we are intentionally ignoring errors, because this is called again by
	// osin.We are only doing this to ensure r.From is properly initialized incase
	// r.ParseForm was success
	r.ParseForm()
	if err := JSONToFormValues(r); err != nil {
		log.Errorf("trying to set url values decoded from json body :%v", err)
	}
	var username string

	if ar := o.OsinServer.HandleAccessRequest(resp, r); ar != nil {

		var session *user.SessionState
		if ar.Type == osin.PASSWORD {
			username = r.Form.Get("username")
			password := r.Form.Get("password")
			searchKey := "apikey-" + storage.HashKey(o.API.OrgID+username, o.Gw.GetConfig().HashKeys)
			log.Debug("Getting: ", searchKey)

			var err error
			session, err = o.OsinServer.Storage.GetUser(searchKey)
			if err != nil {
				log.Warning("Attempted access with non-existent user (OAuth password flow).")
			} else {
				var passMatch bool
				if session.BasicAuthData.Hash == user.HashBCrypt {
					err := bcrypt.CompareHashAndPassword([]byte(session.BasicAuthData.Password), []byte(password))
					if err == nil {
						passMatch = true
					}
				}

				if session.BasicAuthData.Hash == user.HashPlainText &&
					session.BasicAuthData.Password == password {
					passMatch = true
				}

				if passMatch {
					ar.Authorized = true
					// not ideal, but we need to copy the session state across
					pw := session.BasicAuthData.Password
					hs := session.BasicAuthData.Hash

					session.BasicAuthData.Password = ""
					session.BasicAuthData.Hash = ""
					asString, _ := json.Marshal(session)
					ar.UserData = string(asString)

					session.BasicAuthData.Password = pw
					session.BasicAuthData.Hash = hs

					//log.Warning("Old Keys: ", session.OauthKeys)
				}
			}
		} else {
			// Using a manual flow
			ar.Authorized = true
		}

		// Does the user have an old OAuth token for this client?
		if session != nil && session.OauthKeys != nil {
			log.Debug("There's keys here bill...")
			oldToken, foundKey := session.OauthKeys[ar.Client.GetId()]
			if foundKey {
				log.Info("Found old token, revoking: ", oldToken)
				o.Gw.GlobalSessionManager.RemoveSession(o.API.OrgID, oldToken, false)
			}
		}

		log.Debug("[OAuth] Finishing access request ")
		o.OsinServer.FinishAccessRequest(resp, r, ar)
		new_token, foundNewToken := resp.Output["access_token"]
		if username != "" && foundNewToken {
			log.Debug("Updating token data in key")
			if session.OauthKeys == nil {
				session.OauthKeys = make(map[string]string)
			}
			session.OauthKeys[ar.Client.GetId()] = new_token.(string)
			log.Debug("New token: ", new_token.(string))
			log.Debug("Keys: ", session.OauthKeys)

			// add oauth-client user_fields to session's meta
			if userData := ar.Client.GetUserData(); userData != nil {
				metadata, ok := userData.(map[string]interface{})
				if !ok {
					log.WithField("oauthClientID", ar.Client.GetId()).
						Error("Could not set session meta_data from oauth-client fields, type mismatch")
				} else {
					session.MetaData = metadata
					// set session alias to developer email as we do it for regular API keys created for developer
					if devEmail, found := session.MetaData[keyDataDeveloperEmail].(string); found {
						session.Alias = devEmail
						// we don't need it in meta-data as we set it to alias
						delete(session.MetaData, keyDataDeveloperEmail)
					}
				}
			}

			keyName := o.Gw.generateToken(o.API.OrgID, username)

			log.Debug("Updating user:", keyName)
			err := o.Gw.GlobalSessionManager.UpdateSession(keyName, session, session.Lifetime(o.API.GetSessionLifetimeRespectsKeyExpiration(), o.API.SessionLifetime, o.Gw.GetConfig().ForceGlobalSessionLifetime, o.Gw.GetConfig().GlobalSessionLifetime), false)
			if err != nil {
				log.Error(err)
			}
		}
	}
	if resp.IsError {
		clientId := r.Form.Get("client_id")
		log.WithFields(logrus.Fields{
			"org_id":         o.API.OrgID,
			"client_id":      clientId,
			"response error": resp.StatusText,
			"response code":  resp.ErrorStatusCode,
			"RemoteAddr":     request.RealIP(r), //r.RemoteAddr,
		}).Error("[OAuth] OAuth response marked as error")
	}

	return resp
}

// These enums fix the prefix to use when storing various OAuth keys and data, since we
// delegate everything to the osin framework
const (
	prefixAuth            = "oauth-authorize."
	prefixClient          = "oauth-clientid."
	prefixAccess          = "oauth-access."
	prefixRefresh         = "oauth-refresh."
	prefixClientset       = "oauth-clientset."
	prefixClientIndexList = "oauth-client-index."
	prefixClientTokens    = "oauth-client-tokens."
)

// swagger:model
type OAuthClientToken struct {
	Token   string `json:"code"`
	Expires int64  `json:"expires"`
}

type ExtendedOsinClientInterface interface {
	osin.Client
	GetDescription() string
}

type ExtendedOsinStorageInterface interface {
	osin.Storage

	// Create OAuth clients
	SetClient(id string, orgID string, client osin.Client, ignorePrefix bool) error

	// Custom getter to handle prefixing issues in Redis
	GetClientNoPrefix(id string) (osin.Client, error)

	GetClientTokens(id string) ([]OAuthClientToken, error)
	GetPaginatedClientTokens(id string, page int) ([]OAuthClientToken, int, error)

	GetExtendedClient(id string) (ExtendedOsinClientInterface, error)

	// Custom getter to handle prefixing issues in Redis
	GetExtendedClientNoPrefix(id string) (ExtendedOsinClientInterface, error)

	GetClients(filter string, orgID string, ignorePrefix bool) ([]ExtendedOsinClientInterface, error)

	DeleteClient(id string, orgID string, ignorePrefix bool) error

	// GetUser retrieves a Basic Access user token type from the key store
	GetUser(string) (*user.SessionState, error)

	// SetUser updates a Basic Access user token type in the key store
	SetUser(string, *user.SessionState, int64) error
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
func (gw *Gateway) TykOsinNewServer(config *osin.ServerConfig, storage ExtendedOsinStorageInterface) *TykOsinServer {

	overrideServer := TykOsinServer{
		Config:            config,
		Storage:           storage,
		AuthorizeTokenGen: &osin.AuthorizeTokenGenDefault{},
		AccessTokenGen:    accessTokenGen{gw},
	}

	overrideServer.Server.Config = config
	overrideServer.Server.Storage = storage
	overrideServer.Server.AuthorizeTokenGen = overrideServer.AuthorizeTokenGen
	overrideServer.Server.AccessTokenGen = accessTokenGen{gw}

	return &overrideServer
}

// TODO: Refactor this to move prefix handling into a checker method, then it can be an unexported setting in the struct.
// RedisOsinStorageInterface implements osin.Storage interface to use Tyk's own storage mechanism
type RedisOsinStorageInterface struct {
	store          storage.Handler
	sessionManager SessionHandler
	redisStore     storage.Handler
	orgID          string
	Gw             *Gateway `json:"-"`
}

func (r *RedisOsinStorageInterface) Clone() osin.Storage {
	return r
}

func (r *RedisOsinStorageInterface) Close() {}

// GetClient will retrieve client data
func (r *RedisOsinStorageInterface) GetClient(id string) (osin.Client, error) {
	key := prefixClient + id

	log.Debug("Getting client ID:", id)
	clientJSON, err := r.store.GetKey(key)
	if err != nil {
		log.Debugf("Failure retrieving client ID key %q: %v", key, err)
		return nil, err
	}

	client := new(OAuthClient)
	if err := json.Unmarshal([]byte(clientJSON), &client); err != nil {
		log.Debug("Couldn't unmarshal OAuth client object: ", err)
	}
	return client, nil
}

// GetClientNoPrefix will retrieve client data, but not assign a prefix - this is an unfortunate hack,
// but we don't want to change the signature in Osin for GetClient to support the odd Redis prefixing
func (r *RedisOsinStorageInterface) GetClientNoPrefix(id string) (osin.Client, error) {

	key := id

	clientJSON, err := r.store.GetKey(key)

	if err != nil {
		log.Error("Failure retrieving client ID key: ", err)
		return nil, err
	}

	client := new(OAuthClient)
	if err := json.Unmarshal([]byte(clientJSON), client); err != nil {
		log.Error("Couldn't unmarshal OAuth client object: ", err)
	}

	return client, nil
}

func (r *RedisOsinStorageInterface) GetExtendedClient(id string) (ExtendedOsinClientInterface, error) {
	osinClient, err := r.GetClient(id)
	if err != nil {
		log.WithError(err).Error("Failure retrieving client ID key")
		return nil, err
	}

	return osinClient.(*OAuthClient), err
}

// GetExtendedClientNoPrefix custom getter to handle prefixing issues in Redis,
func (r *RedisOsinStorageInterface) GetExtendedClientNoPrefix(id string) (ExtendedOsinClientInterface, error) {
	osinClient, err := r.GetClientNoPrefix(id)
	if err != nil {
		log.WithError(err).Error("Failure retrieving client ID key")
		return nil, err
	}
	return osinClient.(*OAuthClient), err
}

// GetClients will retrieve a list of clients for a prefix
func (r *RedisOsinStorageInterface) GetClients(filter string, orgID string, ignorePrefix bool) ([]ExtendedOsinClientInterface, error) {
	key := prefixClient + filter
	if ignorePrefix {
		key = filter
	}

	indexKey := prefixClientIndexList + orgID

	var clientJSON map[string]string
	if !r.Gw.GetConfig().Storage.EnableCluster {
		exists, _ := r.store.Exists(indexKey)
		if exists {
			keys, err := r.store.GetListRange(indexKey, 0, -1)
			if err != nil {
				log.Error("Couldn't get OAuth client index list: ", err)
				return nil, err
			}
			keyVals, err := r.store.GetMultiKey(keys)
			if err != nil {
				log.Error("Couldn't get OAuth client index list values: ", err)
				return nil, err
			}

			clientJSON = make(map[string]string)
			for i, key := range keys {
				clientJSON[key] = keyVals[i]
			}
		} else {
			clientJSON = r.store.GetKeysAndValuesWithFilter(key)
			for key := range clientJSON {
				r.store.AppendToSet(indexKey, key)
			}
		}
	} else {
		keyForSet := prefixClientset + prefixClient // Org ID
		var err error
		if clientJSON, err = r.store.GetSet(keyForSet); err != nil {
			return nil, err
		}
	}

	theseClients := []ExtendedOsinClientInterface{}
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

// GetPaginatedClientTokens returns all tokens associated with the given id.
// It returns the tokens, the total number of pages of the tokens after
// pagination and an error if any
func (r *RedisOsinStorageInterface) GetPaginatedClientTokens(id string, page int) ([]OAuthClientToken, int, error) {
	key := prefixClientTokens + id

	// use current timestamp as a start score so all expired tokens won't be picked
	nowTs := time.Now().Unix()
	startScore := strconv.FormatInt(nowTs, 10)

	log.Info("Getting client tokens sorted list:", key)

	tokens, scores, err := r.store.GetSortedSetRange(key, startScore, "+inf")
	if err != nil {
		return nil, 0, err
	}

	// clean up expired tokens in sorted set (remove all tokens with score up to current timestamp minus retention)
	if r.Gw.GetConfig().OauthTokenExpiredRetainPeriod > 0 {
		cleanupStartScore := strconv.FormatInt(nowTs-int64(r.Gw.GetConfig().OauthTokenExpiredRetainPeriod), 10)
		go r.store.RemoveSortedSetRange(key, "-inf", cleanupStartScore)
	}

	itemsPerPage := 100

	tokenNumber := len(tokens)

	if tokenNumber == 0 {
		return []OAuthClientToken{}, 0, nil
	}

	startIdx := (page - 1) * itemsPerPage
	endIdx := startIdx + itemsPerPage

	if tokenNumber < startIdx {
		startIdx = tokenNumber
	}

	if tokenNumber < endIdx {
		endIdx = tokenNumber
	}

	totalPages := int(math.Ceil(float64(len(tokens)) / float64(itemsPerPage)))

	tokens = tokens[startIdx:endIdx]

	// convert sorted set data and scores into reply struct
	tokensData := make([]OAuthClientToken, len(tokens))
	for i := range tokens {
		tokensData[i] = OAuthClientToken{
			Token:   tokens[i],
			Expires: int64(scores[i]), // we store expire timestamp as a score
		}
	}

	return tokensData, totalPages, nil
}

func (r *RedisOsinStorageInterface) GetClientTokens(id string) ([]OAuthClientToken, error) {
	key := prefixClientTokens + id

	// use current timestamp as a start score so all expired tokens won't be picked
	nowTs := time.Now().Unix()
	startScore := strconv.FormatInt(nowTs, 10)

	log.Info("Getting client tokens sorted list:", key)

	tokens, scores, err := r.redisStore.GetSortedSetRange(key, startScore, "+inf")
	if err != nil {
		return nil, err
	}

	// clean up expired tokens in sorted set (remove all tokens with score up to current timestamp minus retention)
	if r.Gw.GetConfig().OauthTokenExpiredRetainPeriod > 0 {
		cleanupStartScore := strconv.FormatInt(nowTs-int64(r.Gw.GetConfig().OauthTokenExpiredRetainPeriod), 10)
		go r.redisStore.RemoveSortedSetRange(key, "-inf", cleanupStartScore)
	}

	if len(tokens) == 0 {
		return []OAuthClientToken{}, nil
	}

	// convert sorted set data and scores into reply struct
	tokensData := make([]OAuthClientToken, len(tokens))
	for i := range tokens {
		tokensData[i] = OAuthClientToken{
			Token:   tokens[i],
			Expires: int64(scores[i]), // we store expire timestamp as a score
		}
	}

	return tokensData, nil
}

// SetClient creates client data
func (r *RedisOsinStorageInterface) SetClient(id string, orgID string, client osin.Client, ignorePrefix bool) error {
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

	err = r.store.SetKey(key, string(clientDataJSON), 0)
	if err != nil {
		log.WithError(err).Error("could not save oauth client data")
	}

	keyForSet := prefixClientset + prefixClient // Org ID

	indexKey := prefixClientIndexList + orgID
	//check if the indexKey exists
	exists, err := r.store.Exists(indexKey)
	if err != nil {
		return err
	}
	// if it exists, delete it to avoid duplicity in the client index list
	if exists {
		r.store.RemoveFromList(indexKey, key)
	}
	// append to oauth client index list
	r.store.AppendToSet(indexKey, key)

	// In set, there is no option for update so the existing client should be removed before adding new one.
	set, _ := r.store.GetSet(keyForSet)
	for _, v := range set {
		if strings.Contains(v, client.GetId()) {
			r.store.RemoveFromSet(keyForSet, v)
		}
	}

	r.store.AddToSet(keyForSet, string(clientDataJSON))
	return nil
}

// DeleteClient Removes a client from the system
func (r *RedisOsinStorageInterface) DeleteClient(id string, orgID string, ignorePrefix bool) error {
	key := prefixClient + id
	if ignorePrefix {
		key = id
	}

	// Get the raw vals:
	clientJSON, err := r.store.GetKey(key)
	keyForSet := prefixClientset + prefixClient // Org ID
	if err == nil {
		log.Debug("Removing from set")
		r.store.RemoveFromSet(keyForSet, clientJSON)
	}

	r.store.DeleteKey(key)

	indexKey := prefixClientIndexList + orgID
	// delete from oauth client
	r.store.RemoveFromList(indexKey, key)

	// delete list of tokens for this client
	r.store.DeleteKey(prefixClientTokens + id)
	if r.Gw.GetConfig().SlaveOptions.UseRPC {
		r.redisStore.RemoveFromList(indexKey, key)
		r.redisStore.DeleteKey(prefixClientTokens + id)
		r.redisStore.RemoveFromSet(keyForSet, clientJSON)
	}

	return nil
}

// SaveAuthorize saves authorisation data to Redis
func (r *RedisOsinStorageInterface) SaveAuthorize(authData *osin.AuthorizeData) error {
	authDataJSON, err := json.Marshal(&authData)
	if err != nil {
		return err
	}
	key := prefixAuth + authData.Code
	log.Debug("Saving auth code: ", key)

	err = r.store.SetKey(key, string(authDataJSON), int64(authData.ExpiresIn))

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

	authData := osin.AuthorizeData{Client: new(OAuthClient)}
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
	key := prefixAccess + storage.HashKey(accessData.AccessToken, r.Gw.GetConfig().HashKeys)
	log.Debug("Saving ACCESS key: ", key)

	// Overide default ExpiresIn:
	if oauthTokenExpire := r.Gw.GetConfig().OauthTokenExpire; oauthTokenExpire != 0 {
		accessData.ExpiresIn = oauthTokenExpire
	}

	err = r.store.SetKey(key, string(authDataJSON), int64(accessData.ExpiresIn))
	if err != nil {
		log.WithError(err).Error("could not save access data")
	}

	// add code to list of tokens for this client
	sortedListKey := prefixClientTokens + accessData.Client.GetId()
	log.Debug("Adding ACCESS key to sorted list: ", sortedListKey)
	r.redisStore.AddToSortedSet(
		sortedListKey,
		storage.HashKey(accessData.AccessToken, r.Gw.GetConfig().HashKeys),
		float64(accessData.CreatedAt.Unix()+int64(accessData.ExpiresIn)), // set score as token expire timestamp
	)

	// Create a user.SessionState object and register it with the authmanager
	newSession := user.NewSessionState()

	// ------
	checkPolicy := true
	if accessData.UserData != nil {
		checkPolicy = false
		err := json.Unmarshal([]byte(accessData.UserData.(string)), newSession)
		if err != nil {
			log.Info("Couldn't decode user.SessionState from UserData, checking policy: ", err)
			checkPolicy = true
		}
	}

	if checkPolicy {
		// defined in JWT middleware
		sessionFromPolicy, err := r.Gw.generateSessionFromPolicy(accessData.Client.GetPolicyID(), "", false)
		if err != nil {
			return errors.New("Couldn't use policy or key rules to create token, failing")
		}

		newSession = &sessionFromPolicy
	}

	// ------

	// Set the client ID for analytics
	newSession.OauthClientID = accessData.Client.GetId()

	// Override timeouts so that we can be in sync with Osin
	newSession.Expires = time.Now().Unix() + int64(accessData.ExpiresIn)

	c, ok := accessData.Client.(*OAuthClient)
	if ok && c.MetaData != nil {
		if newSession.MetaData == nil {
			newSession.MetaData = make(map[string]interface{})
		}

		// Allow session inherit and *override* client values
		for k, v := range c.MetaData.(map[string]interface{}) {
			if _, found := newSession.MetaData[k]; !found {
				newSession.MetaData[k] = v
			}
		}
	}

	// Use the default session expiry here as this is OAuth
	r.sessionManager.UpdateSession(accessData.AccessToken, newSession, int64(accessData.ExpiresIn), false)

	// Store the refresh token too
	if accessData.RefreshToken != "" {
		accessDataJSON, err := json.Marshal(accessData)
		if err != nil {
			return err
		}
		key := prefixRefresh + accessData.RefreshToken
		refreshExpire := int64(1209600) // 14 days
		if oauthRefreshExpire := r.Gw.GetConfig().OauthRefreshExpire; oauthRefreshExpire != 0 {
			refreshExpire = oauthRefreshExpire
		}
		log.Debug("STORING ACCESS DATA: ", string(accessDataJSON))
		err = r.store.SetKey(key, string(accessDataJSON), refreshExpire)
		if err != nil {
			log.WithError(err).Error("could not save access data")
		}
		return err
	}

	return nil
}

// LoadAccess will load access data from redis
func (r *RedisOsinStorageInterface) LoadAccess(token string) (*osin.AccessData, error) {
	key := prefixAccess + storage.HashKey(token, r.Gw.GetConfig().HashKeys)
	log.Debug("Loading ACCESS key: ", key)
	accessJSON, err := r.store.GetKey(key)

	if err != nil {
		// Fallback to unhashed value for backward compatibility
		key = prefixAccess + token
		accessJSON, err = r.store.GetKey(key)

		if err != nil {
			log.Error("Failure retreiving access token by key: ", err)
			return nil, err
		}
	}

	accessData := osin.AccessData{Client: new(OAuthClient)}
	if err := json.Unmarshal([]byte(accessJSON), &accessData); err != nil {
		log.Error("Couldn't unmarshal OAuth auth data object (LoadAccess): ", err)
		return nil, err
	}

	return &accessData, nil
}

// RemoveAccess will remove access data from Redis
func (r *RedisOsinStorageInterface) RemoveAccess(token string) error {

	access, err := r.LoadAccess(token)
	if err == nil {
		key := prefixClientTokens + access.Client.GetId()
		//remove from set oauth.client-tokens
		log.Info("removing token from oauth client tokens list")
		limit := strconv.FormatFloat(float64(access.ExpireAt().Unix()), 'f', 0, 64)
		r.redisStore.RemoveSortedSetRange(key, limit, limit)
	} else {
		log.Warning("Cannot load access token:", token)
	}

	key := prefixAccess + storage.HashKey(token, r.Gw.GetConfig().HashKeys)
	r.store.DeleteKey(key)
	// remove the access token from central storage too
	r.sessionManager.RemoveSession(r.orgID, token, false)
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
	accessData := osin.AccessData{Client: new(OAuthClient)}
	if err := json.Unmarshal([]byte(accessJSON), &accessData); err != nil {
		log.Error("Couldn't unmarshal OAuth auth data object (LoadRefresh): ", err,
			"; Decoding: ", accessJSON)
		return nil, err
	}

	return &accessData, nil
}

// RemoveRefresh will remove a refresh token from redis
func (r *RedisOsinStorageInterface) RemoveRefresh(token string) error {
	log.Debug("is going to revoke refresh token: ", token)
	key := prefixRefresh + token
	r.store.DeleteKey(key)
	return nil
}

// accessTokenGen is a modified authorization token generator that uses the same method used to generate tokens for Tyk authHandler
type accessTokenGen struct {
	Gw *Gateway `json:"-"`
}

// GenerateAccessToken generates base64-encoded UUID access and refresh tokens
func (a accessTokenGen) GenerateAccessToken(data *osin.AccessData, generaterefresh bool) (accesstoken, refreshtoken string, err error) {
	log.Info("[OAuth] Generating new token")

	var newSession user.SessionState
	checkPolicy := true
	if data.UserData != nil {
		checkPolicy = false
		err := json.Unmarshal([]byte(data.UserData.(string)), &newSession)
		if err != nil {
			log.Info("[GenerateAccessToken] Couldn't decode user.SessionState from UserData, checking policy: ", err)
			checkPolicy = true
		}
	}

	if checkPolicy {
		// defined in JWT middleware
		sessionFromPolicy, err := a.Gw.generateSessionFromPolicy(data.Client.GetPolicyID(), "", false)
		if err != nil {
			return "", "", errors.New("Couldn't use policy or key rules to create token, failing")
		}

		newSession = sessionFromPolicy.Clone()
	}

	accesstoken = a.Gw.keyGen.GenerateAuthKey(newSession.OrgID)
	if generaterefresh {
		u6 := uuid.NewV4()
		refreshtoken = base64.StdEncoding.EncodeToString([]byte(u6.String()))
	}
	return
}

// LoadRefresh will load access data from Redis
func (r *RedisOsinStorageInterface) GetUser(username string) (*user.SessionState, error) {
	key := username
	log.Debug("Loading User key: ", key)
	accessJSON, err := r.store.GetRawKey(key)

	if err != nil {
		log.Error("Failure retreiving access token by key: ", err)
		return nil, err
	}

	// new interface means having to make this nested... ick.
	session := &user.SessionState{}
	if err := json.Unmarshal([]byte(accessJSON), session); err != nil {
		log.Error("Couldn't unmarshal OAuth auth data object (LoadRefresh): ", err,
			"; Decoding: ", accessJSON)
		return nil, err
	}

	return session, nil
}

func (r *RedisOsinStorageInterface) SetUser(username string, session *user.SessionState, timeout int64) error {
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
