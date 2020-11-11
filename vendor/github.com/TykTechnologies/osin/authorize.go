package osin

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

// AuthorizeRequestType is the type for OAuth param `response_type`
type AuthorizeRequestType string

const (
	CODE  AuthorizeRequestType = "code"
	TOKEN AuthorizeRequestType = "token"

	PKCE_PLAIN = "plain"
	PKCE_S256  = "S256"
)

var (
	pkceMatcher = regexp.MustCompile("^[a-zA-Z0-9~._-]{43,128}$")
)

// Authorize request information
type AuthorizeRequest struct {
	Type        AuthorizeRequestType
	Client      Client
	Scope       string
	RedirectUri string
	State       string

	// Set if request is authorized
	Authorized bool

	// Token expiration in seconds. Change if different from default.
	// If type = TOKEN, this expiration will be for the ACCESS token.
	Expiration int32

	// Data to be passed to storage. Not used by the library.
	UserData interface{}

	// HttpRequest *http.Request for special use
	HttpRequest *http.Request

	// Optional code_challenge as described in rfc7636
	CodeChallenge string
	// Optional code_challenge_method as described in rfc7636
	CodeChallengeMethod string
}

// Authorization data
type AuthorizeData struct {
	// Client information
	Client Client `json:",omitempty"`

	// Authorization code
	Code string

	// Token expiration in seconds
	ExpiresIn int32

	// Requested scope
	Scope string

	// Redirect Uri from request
	RedirectUri string

	// State data from request
	State string

	// Date created
	CreatedAt time.Time

	// Data to be passed to storage. Not used by the library.
	UserData interface{} `json:",omitempty"`

	// Optional code_challenge as described in rfc7636
	CodeChallenge string
	// Optional code_challenge_method as described in rfc7636
	CodeChallengeMethod string
}

type authorizeData AuthorizeData

func (c *AuthorizeData) UnmarshalJSON(b []byte) error {
	newAuthData := authorizeData{}
	newAuthData.Client = new(DefaultClient)
	// var code, scope, redirect, state string
	// var expires int32
	// var createdAt time.Time
	// var userData interface{}
	var err error

	if err = json.Unmarshal(b, &newAuthData); err == nil {
		*c = AuthorizeData(newAuthData)
		return nil
	}
	return nil
}

// IsExpired is true if authorization expired
func (d *AuthorizeData) IsExpired() bool {
	return d.IsExpiredAt(time.Now())
}

// IsExpired is true if authorization expires at time 't'
func (d *AuthorizeData) IsExpiredAt(t time.Time) bool {
	return d.ExpireAt().Before(t)
}

// ExpireAt returns the expiration date
func (d *AuthorizeData) ExpireAt() time.Time {
	return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second)
}

// AuthorizeTokenGen is the token generator interface
type AuthorizeTokenGen interface {
	GenerateAuthorizeToken(data *AuthorizeData) (string, error)
}

// HandleAuthorizeRequest is the main http.HandlerFunc for handling
// authorization requests
func (s *Server) HandleAuthorizeRequest(w *Response, r *http.Request) *AuthorizeRequest {
	r.ParseForm()

	// create the authorization request
	unescapedUri, err := url.QueryUnescape(r.FormValue("redirect_uri"))
	if err != nil {
		w.SetErrorState(E_INVALID_REQUEST, "", "")
		w.InternalError = err
		return nil
	}

	ret := &AuthorizeRequest{
		State:       r.FormValue("state"),
		Scope:       r.FormValue("scope"),
		RedirectUri: unescapedUri,
		Authorized:  false,
		HttpRequest: r,
	}

	// must have a valid client
	ret.Client, err = w.Storage.GetClient(r.FormValue("client_id"))
	if err == ErrNotFound {
		w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
		return nil
	}
	if err != nil {
		w.SetErrorState(E_SERVER_ERROR, "", ret.State)
		w.InternalError = err
		return nil
	}
	if ret.Client == nil {
		w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
		return nil
	}
	if ret.Client.GetRedirectUri() == "" {
		w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
		return nil
	}

	// check redirect uri, if there are multiple client redirect uri's
	// don't set the uri
	if ret.RedirectUri == "" && FirstUri(ret.Client.GetRedirectUri(), s.Config.RedirectUriSeparator) == ret.Client.GetRedirectUri() {
		ret.RedirectUri = FirstUri(ret.Client.GetRedirectUri(), s.Config.RedirectUriSeparator)
	}

	if realRedirectUri, err := ValidateUriList(ret.Client.GetRedirectUri(), ret.RedirectUri, s.Config.RedirectUriSeparator); err != nil {
		w.SetErrorState(E_INVALID_REQUEST, "", ret.State)
		w.InternalError = err
		return nil
	} else {
		ret.RedirectUri = realRedirectUri
	}

	w.SetRedirect(ret.RedirectUri)

	requestType := AuthorizeRequestType(r.FormValue("response_type"))
	if s.Config.AllowedAuthorizeTypes.Exists(requestType) {
		switch requestType {
		case CODE:
			ret.Type = CODE
			ret.Expiration = s.Config.AuthorizationExpiration

			// Optional PKCE support (https://tools.ietf.org/html/rfc7636)
			if codeChallenge := r.FormValue("code_challenge"); len(codeChallenge) == 0 {
				if s.Config.RequirePKCEForPublicClients && CheckClientSecret(ret.Client, "") {
					// https://tools.ietf.org/html/rfc7636#section-4.4.1
					w.SetErrorState(E_INVALID_REQUEST, "code_challenge (rfc7636) required for public clients", ret.State)
					return nil
				}
			} else {
				codeChallengeMethod := r.FormValue("code_challenge_method")
				// allowed values are "plain" (default) and "S256", per https://tools.ietf.org/html/rfc7636#section-4.3
				if len(codeChallengeMethod) == 0 {
					codeChallengeMethod = PKCE_PLAIN
				}
				if codeChallengeMethod != PKCE_PLAIN && codeChallengeMethod != PKCE_S256 {
					// https://tools.ietf.org/html/rfc7636#section-4.4.1
					w.SetErrorState(E_INVALID_REQUEST, "code_challenge_method transform algorithm not supported (rfc7636)", ret.State)
					return nil
				}

				// https://tools.ietf.org/html/rfc7636#section-4.2
				if matched := pkceMatcher.MatchString(codeChallenge); !matched {
					w.SetErrorState(E_INVALID_REQUEST, "code_challenge invalid (rfc7636)", ret.State)
					return nil
				}

				ret.CodeChallenge = codeChallenge
				ret.CodeChallengeMethod = codeChallengeMethod
			}

		case TOKEN:
			ret.Type = TOKEN
			ret.Expiration = s.Config.AccessExpiration
		}
		return ret
	}

	w.SetErrorState(E_UNSUPPORTED_RESPONSE_TYPE, "", ret.State)
	return nil
}

func (s *Server) FinishAuthorizeRequest(w *Response, r *http.Request, ar *AuthorizeRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}

	// force redirect response
	w.SetRedirect(ar.RedirectUri)

	if ar.Authorized {
		if ar.Type == TOKEN {
			w.SetRedirectFragment(true)

			// generate token directly
			ret := &AccessRequest{
				Type:            IMPLICIT,
				Code:            "",
				Client:          ar.Client,
				RedirectUri:     ar.RedirectUri,
				Scope:           ar.Scope,
				GenerateRefresh: false, // per the RFC, should NOT generate a refresh token in this case
				Authorized:      true,
				Expiration:      ar.Expiration,
				UserData:        ar.UserData,
			}

			s.FinishAccessRequest(w, r, ret)
			if ar.State != "" && w.InternalError == nil {
				w.Output["state"] = ar.State
			}
		} else {
			// generate authorization token
			ret := &AuthorizeData{
				Client:      ar.Client,
				CreatedAt:   s.Now(),
				ExpiresIn:   ar.Expiration,
				RedirectUri: ar.RedirectUri,
				State:       ar.State,
				Scope:       ar.Scope,
				UserData:    ar.UserData,
				// Optional PKCE challenge
				CodeChallenge:       ar.CodeChallenge,
				CodeChallengeMethod: ar.CodeChallengeMethod,
			}

			// generate token code
			code, err := s.AuthorizeTokenGen.GenerateAuthorizeToken(ret)
			if err != nil {
				w.SetErrorState(E_SERVER_ERROR, "", ar.State)
				w.InternalError = err
				return
			}
			ret.Code = code

			// save authorization token
			if err = w.Storage.SaveAuthorize(ret); err != nil {
				w.SetErrorState(E_SERVER_ERROR, "", ar.State)
				w.InternalError = err
				return
			}

			// redirect with code
			w.Output["code"] = ret.Code
			w.Output["state"] = ret.State
		}
	} else {
		// redirect with error
		w.SetErrorState(E_ACCESS_DENIED, "", ar.State)
	}
}
