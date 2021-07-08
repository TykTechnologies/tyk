package osin

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// AccessRequestType is the type for OAuth param `grant_type`
type AccessRequestType string

const (
	AUTHORIZATION_CODE AccessRequestType = "authorization_code"
	REFRESH_TOKEN      AccessRequestType = "refresh_token"
	PASSWORD           AccessRequestType = "password"
	CLIENT_CREDENTIALS AccessRequestType = "client_credentials"
	ASSERTION          AccessRequestType = "assertion"
	IMPLICIT           AccessRequestType = "__implicit"
)

// AccessRequest is a request for access tokens
type AccessRequest struct {
	Type          AccessRequestType
	Code          string
	Client        Client         `json:",omitempty"`
	AuthorizeData *AuthorizeData `json:",omitempty"`
	AccessData    *AccessData    `json:",omitempty"`

	// Force finish to use this access data, to allow access data reuse
	ForceAccessData *AccessData
	RedirectUri     string
	Scope           string
	Username        string
	Password        string
	AssertionType   string
	Assertion       string

	// Set if request is authorized
	Authorized bool

	// Token expiration in seconds. Change if different from default
	Expiration int32

	// Set if a refresh token should be generated
	GenerateRefresh bool

	// Data to be passed to storage. Not used by the library.
	UserData interface{}

	// HttpRequest *http.Request for special use
	HttpRequest *http.Request

	// Optional code_verifier as described in rfc7636
	CodeVerifier string
}

// AccessData represents an access grant (tokens, expiration, client, etc)
type AccessData struct {
	// Client information
	Client Client `json:",omitempty"`

	// Authorize data, for authorization code
	AuthorizeData *AuthorizeData `json:",omitempty"`

	// Previous access data, for refresh token
	AccessData *AccessData `json:",omitempty"`

	// Access token
	AccessToken string

	// Refresh Token. Can be blank
	RefreshToken string

	// Token expiration in seconds
	ExpiresIn int32

	// Requested scope
	Scope string

	// Redirect Uri from request
	RedirectUri string

	// Date created
	CreatedAt time.Time

	// Data to be passed to storage. Not used by the library.
	UserData interface{}
}

type accessData AccessData

func (c *AccessData) UnmarshalJSON(b []byte) error {
	newAccessData := accessData{}
	newAccessData.Client = new(DefaultClient)
	var err error

	if err = json.Unmarshal(b, &newAccessData); err == nil {
		*c = AccessData(newAccessData)
		return nil
	}
	return nil
}

// IsExpired returns true if access expired
func (d *AccessData) IsExpired() bool {
	return d.IsExpiredAt(time.Now())
}

// IsExpiredAt returns true if access expires at time 't'
func (d *AccessData) IsExpiredAt(t time.Time) bool {
	return d.ExpireAt().Before(t)
}

// ExpireAt returns the expiration date
func (d *AccessData) ExpireAt() time.Time {
	return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second)
}

// AccessTokenGen generates access tokens
type AccessTokenGen interface {
	GenerateAccessToken(data *AccessData, generaterefresh bool) (accesstoken string, refreshtoken string, err error)
}

// HandleAccessRequest is the http.HandlerFunc for handling access token requests
func (s *Server) HandleAccessRequest(w *Response, r *http.Request) *AccessRequest {
	// Only allow GET or POST
	if r.Method == "GET" {
		if !s.Config.AllowGetAccessRequest {
			s.setErrorAndLog(w, E_INVALID_REQUEST, errors.New("Request must be POST"), "access_request=%s", "GET request not allowed")
			return nil
		}
	} else if r.Method != "POST" {
		s.setErrorAndLog(w, E_INVALID_REQUEST, errors.New("Request must be POST"), "access_request=%s", "request must be POST")
		return nil
	}

	err := r.ParseForm()
	if err != nil {
		s.setErrorAndLog(w, E_INVALID_REQUEST, err, "access_request=%s", "parsing error")
		return nil
	}

	grantType := AccessRequestType(r.FormValue("grant_type"))
	if s.Config.AllowedAccessTypes.Exists(grantType) {
		switch grantType {
		case AUTHORIZATION_CODE:
			return s.handleAuthorizationCodeRequest(w, r)
		case REFRESH_TOKEN:
			return s.handleRefreshTokenRequest(w, r)
		case PASSWORD:
			return s.handlePasswordRequest(w, r)
		case CLIENT_CREDENTIALS:
			return s.handleClientCredentialsRequest(w, r)
		case ASSERTION:
			return s.handleAssertionRequest(w, r)
		}
	}

	s.setErrorAndLog(w, E_UNSUPPORTED_GRANT_TYPE, nil, "access_request=%s", "unknown grant type")
	return nil
}

func (s *Server) handleAuthorizationCodeRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := s.getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            AUTHORIZATION_CODE,
		Code:            r.FormValue("code"),
		CodeVerifier:    r.FormValue("code_verifier"),
		RedirectUri:     r.FormValue("redirect_uri"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
		HttpRequest:     r,
	}

	// "code" is required
	if ret.Code == "" {
		s.setErrorAndLog(w, E_INVALID_GRANT, nil, "auth_code_request=%s", "code is required")
		return nil
	}

	// must have a valid client
	if ret.Client = s.getClient(auth, w.Storage, w); ret.Client == nil {
		return nil
	}

	// must be a valid authorization code
	var err error
	ret.AuthorizeData, err = w.Storage.LoadAuthorize(ret.Code)
	if err != nil {
		s.setErrorAndLog(w, E_INVALID_GRANT, err, "auth_code_request=%s", "error loading authorize data")
		return nil
	}
	if ret.AuthorizeData == nil {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "auth_code_request=%s", "authorization data is nil")
		return nil
	}
	if ret.AuthorizeData.Client == nil {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "auth_code_request=%s", "authorization client is nil")
		return nil
	}
	if ret.AuthorizeData.Client.GetRedirectUri() == "" {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "auth_code_request=%s", "client redirect uri is empty")
		return nil
	}
	if ret.AuthorizeData.IsExpiredAt(s.Now()) {
		s.setErrorAndLog(w, E_INVALID_GRANT, nil, "auth_code_request=%s", "authorization data is expired")
		return nil
	}

	// code must be from the client
	if ret.AuthorizeData.Client.GetId() != ret.Client.GetId() {
		s.setErrorAndLog(w, E_INVALID_GRANT, nil, "auth_code_request=%s", "client code does not match")
		return nil
	}

	// check redirect uri
	if ret.RedirectUri == "" {
		ret.RedirectUri = FirstUri(ret.Client.GetRedirectUri(), s.Config.RedirectUriSeparator)
	}
	if realRedirectUri, err := ValidateUriList(ret.Client.GetRedirectUri(), ret.RedirectUri, s.Config.RedirectUriSeparator); err != nil {
		s.setErrorAndLog(w, E_INVALID_REQUEST, err, "auth_code_request=%s", "error validating client redirect")
		return nil
	} else {
		ret.RedirectUri = realRedirectUri
	}
	if ret.AuthorizeData.RedirectUri != ret.RedirectUri {
		s.setErrorAndLog(w, E_INVALID_REQUEST, errors.New("Redirect uri is different"), "auth_code_request=%s", "client redirect does not match authorization data")
		return nil
	}

	// Verify PKCE, if present in the authorization data
	if len(ret.AuthorizeData.CodeChallenge) > 0 {
		// https://tools.ietf.org/html/rfc7636#section-4.1
		if matched := pkceMatcher.MatchString(ret.CodeVerifier); !matched {
			s.setErrorAndLog(w, E_INVALID_REQUEST, errors.New("code_verifier has invalid format"),
				"auth_code_request=%s", "pkce code challenge verifier does not match")
			return nil
		}

		// https: //tools.ietf.org/html/rfc7636#section-4.6
		codeVerifier := ""
		switch ret.AuthorizeData.CodeChallengeMethod {
		case "", PKCE_PLAIN:
			codeVerifier = ret.CodeVerifier
		case PKCE_S256:
			hash := sha256.Sum256([]byte(ret.CodeVerifier))
			codeVerifier = base64.RawURLEncoding.EncodeToString(hash[:])
		default:
			s.setErrorAndLog(w, E_INVALID_REQUEST, nil,
				"auth_code_request=%s", "pkce transform algorithm not supported (rfc7636)")
			return nil
		}
		if codeVerifier != ret.AuthorizeData.CodeChallenge {
			s.setErrorAndLog(w, E_INVALID_GRANT, errors.New("code_verifier failed comparison with code_challenge"),
				"auth_code_request=%s", "pkce code verifier does not match challenge")
			return nil
		}
	}

	// set rest of data
	ret.Scope = ret.AuthorizeData.Scope
	ret.UserData = ret.AuthorizeData.UserData

	return ret
}

func extraScopes(access_scopes, refresh_scopes string) bool {
	access_scopes_list := strings.Split(access_scopes, " ")
	refresh_scopes_list := strings.Split(refresh_scopes, " ")

	access_map := make(map[string]int)

	for _, scope := range access_scopes_list {
		if scope == "" {
			continue
		}
		access_map[scope] = 1
	}

	for _, scope := range refresh_scopes_list {
		if scope == "" {
			continue
		}
		if _, ok := access_map[scope]; !ok {
			return true
		}
	}
	return false
}

func (s *Server) handleRefreshTokenRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := s.getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            REFRESH_TOKEN,
		Code:            r.FormValue("refresh_token"),
		Scope:           r.FormValue("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
		HttpRequest:     r,
	}

	// "refresh_token" is required
	if ret.Code == "" {
		s.setErrorAndLog(w, E_INVALID_GRANT, nil, "refresh_token=%s", "refresh_token is required")
		return nil
	}

	// must have a valid client
	if ret.Client = s.getClient(auth, w.Storage, w); ret.Client == nil {
		return nil
	}

	// must be a valid refresh code
	var err error
	ret.AccessData, err = w.Storage.LoadRefresh(ret.Code)
	if err != nil {
		s.setErrorAndLog(w, E_INVALID_GRANT, err, "refresh_token=%s", "error loading access data")
		return nil
	}
	if ret.AccessData == nil {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "refresh_token=%s", "access data is nil")
		return nil
	}
	if ret.AccessData.Client == nil {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "refresh_token=%s", "access data client is nil")
		return nil
	}
	if ret.AccessData.Client.GetRedirectUri() == "" {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "refresh_token=%s", "access data client redirect uri is empty")
		return nil
	}

	// client must be the same as the previous token
	if ret.AccessData.Client.GetId() != ret.Client.GetId() {
		s.setErrorAndLog(w, E_INVALID_CLIENT, errors.New("Client id must be the same from previous token"), "refresh_token=%s, current=%v, previous=%v", "client mismatch", ret.Client.GetId(), ret.AccessData.Client.GetId())
		return nil

	}

	// set rest of data
	ret.RedirectUri = ret.AccessData.RedirectUri
	ret.UserData = ret.AccessData.UserData
	if ret.Scope == "" {
		ret.Scope = ret.AccessData.Scope
	}

	if extraScopes(ret.AccessData.Scope, ret.Scope) {
		msg := "the requested scope must not include any scope not originally granted by the resource owner"
		s.setErrorAndLog(w, E_ACCESS_DENIED, errors.New(msg), "refresh_token=%s", msg)
		return nil
	}

	return ret
}

func (s *Server) handlePasswordRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := s.getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            PASSWORD,
		Username:        r.FormValue("username"),
		Password:        r.FormValue("password"),
		Scope:           r.FormValue("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
		HttpRequest:     r,
	}

	// "username" and "password" is required
	if ret.Username == "" || ret.Password == "" {
		s.setErrorAndLog(w, E_INVALID_GRANT, nil, "handle_password=%s", "username and pass required")
		return nil
	}

	// must have a valid client
	if ret.Client = s.getClient(auth, w.Storage, w); ret.Client == nil {
		return nil
	}

	// set redirect uri
	ret.RedirectUri = FirstUri(ret.Client.GetRedirectUri(), s.Config.RedirectUriSeparator)

	return ret
}

func (s *Server) handleClientCredentialsRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := s.getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            CLIENT_CREDENTIALS,
		Scope:           r.FormValue("scope"),
		GenerateRefresh: false,
		Expiration:      s.Config.AccessExpiration,
		HttpRequest:     r,
	}

	// must have a valid client
	if ret.Client = s.getClient(auth, w.Storage, w); ret.Client == nil {
		return nil
	}

	// set redirect uri
	ret.RedirectUri = FirstUri(ret.Client.GetRedirectUri(), s.Config.RedirectUriSeparator)

	return ret
}

func (s *Server) handleAssertionRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := s.getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            ASSERTION,
		Scope:           r.FormValue("scope"),
		AssertionType:   r.FormValue("assertion_type"),
		Assertion:       r.FormValue("assertion"),
		GenerateRefresh: false, // assertion should NOT generate a refresh token, per the RFC
		Expiration:      s.Config.AccessExpiration,
		HttpRequest:     r,
	}

	// "assertion_type" and "assertion" is required
	if ret.AssertionType == "" || ret.Assertion == "" {
		s.setErrorAndLog(w, E_INVALID_GRANT, nil, "handle_assertion_request=%s", "assertion and assertion_type required")
		return nil
	}

	// must have a valid client
	if ret.Client = s.getClient(auth, w.Storage, w); ret.Client == nil {
		return nil
	}

	// set redirect uri
	ret.RedirectUri = FirstUri(ret.Client.GetRedirectUri(), s.Config.RedirectUriSeparator)

	return ret
}

func (s *Server) FinishAccessRequest(w *Response, r *http.Request, ar *AccessRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}
	redirectUri := r.FormValue("redirect_uri")
	// Get redirect uri from AccessRequest if it's there (e.g., refresh token request)
	if ar.RedirectUri != "" {
		redirectUri = ar.RedirectUri
	}
	if ar.Authorized {
		var ret *AccessData
		var err error

		if ar.ForceAccessData == nil {
			// generate access token
			ret = &AccessData{
				Client:        ar.Client,
				AuthorizeData: ar.AuthorizeData,
				AccessData:    ar.AccessData,
				RedirectUri:   redirectUri,
				CreatedAt:     s.Now(),
				ExpiresIn:     ar.Expiration,
				UserData:      ar.UserData,
				Scope:         ar.Scope,
			}

			// generate access token
			ret.AccessToken, ret.RefreshToken, err = s.AccessTokenGen.GenerateAccessToken(ret, ar.GenerateRefresh)
			if err != nil {
				s.setErrorAndLog(w, E_SERVER_ERROR, err, "finish_access_request=%s", "error generating token")
				return
			}
		} else {
			ret = ar.ForceAccessData
		}

		// save access token
		if err = w.Storage.SaveAccess(ret); err != nil {
			s.setErrorAndLog(w, E_SERVER_ERROR, err, "finish_access_request=%s", "error saving access token")
			return
		}

		// remove authorization token
		if ret.AuthorizeData != nil {
			w.Storage.RemoveAuthorize(ret.AuthorizeData.Code)
		}

		// remove previous access token
		if ret.AccessData != nil && !s.Config.RetainTokenAfterRefresh {
			if ret.AccessData.RefreshToken != "" {
				w.Storage.RemoveRefresh(ret.AccessData.RefreshToken)
			}
			w.Storage.RemoveAccess(ret.AccessData.AccessToken)
		}

		// output data
		w.Output["access_token"] = ret.AccessToken
		w.Output["token_type"] = s.Config.TokenType
		w.Output["expires_in"] = ret.ExpiresIn
		if ret.RefreshToken != "" {
			w.Output["refresh_token"] = ret.RefreshToken
		}
		if ret.Scope != "" {
			w.Output["scope"] = ret.Scope
		}
	} else {
		s.setErrorAndLog(w, E_ACCESS_DENIED, nil, "finish_access_request=%s", "authorization failed")
	}
}

// Helper Functions

// getClient looks up and authenticates the basic auth using the given
// storage. Sets an error on the response if auth fails or a server error occurs.
func (s Server) getClient(auth *BasicAuth, storage Storage, w *Response) Client {
	client, err := storage.GetClient(auth.Username)
	if err == ErrNotFound {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "get_client=%s", "not found")
		return nil
	}
	if err != nil {
		s.setErrorAndLog(w, E_SERVER_ERROR, err, "get_client=%s", "error finding client")
		return nil
	}
	if client == nil {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "get_client=%s", "client is nil")
		return nil
	}

	if !CheckClientSecret(client, auth.Password) {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "get_client=%s, client_id=%v", "client check failed", client.GetId())
		return nil
	}

	if client.GetRedirectUri() == "" {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "get_client=%s", "client redirect uri is empty")
		return nil
	}
	return client
}

// setErrorAndLog sets the response error and internal error (if non-nil) and logs them along with the provided debug format string and arguments.
func (s Server) setErrorAndLog(w *Response, responseError string, internalError error, debugFormat string, debugArgs ...interface{}) {
	format := "error=%v, internal_error=%#v " + debugFormat

	w.InternalError = internalError
	w.SetError(responseError, "")

	s.Logger.Printf(format, append([]interface{}{responseError, internalError}, debugArgs...)...)
}
