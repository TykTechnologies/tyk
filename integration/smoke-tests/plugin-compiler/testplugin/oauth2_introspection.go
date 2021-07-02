package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/TykTechnologies/tyk/log"
)

var (
	introspectionClient *http.Client
	introspectLogger    = log.Get()

	introspectionEndpoint    = ""
	authorizationHeaderName  = "authorization"
	authorizationHeaderValue = ""
)

func init() {
	introspectionClient = &http.Client{}

	introspectionEndpoint = os.Getenv("OAUTH2_INTROSPECT_ENDPOINT")
	authorizationHeaderValue = os.Getenv("OAUTH2_INTROSPECT_AUTHORIZATION")
}

// AddFooBarHeader adds custom "Foo: Bar" header to the request
//nolint:deadcode
func AddFooBarHeader(rw http.ResponseWriter, r *http.Request) {
	r.Header.Add("Foo", "Bar")
}

func OAuth2Introspect(w http.ResponseWriter, r *http.Request) {
	bearerToken := accessTokenFromRequest(r)
	if bearerToken == "" {
		introspectLogger.Debug("no bearer token found in request")
		writeUnauthorized(w)
		return
	}

	data := url.Values{}
	data.Set("token", bearerToken)
	data.Set("token_type_hint", "access_token")
	introspectionReq, err := http.NewRequest(http.MethodPost, introspectionEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		introspectLogger.Errorf("unable to create new request %s", err.Error())
		writeInternalServerError(w)
		return
	}

	introspectionReq.Header.Add(authorizationHeaderName, authorizationHeaderValue)
	introspectionReq.Header.Add("content-length", strconv.Itoa(len(data.Encode())))
	introspectionReq.Header.Add("content-type", "application/x-www-form-urlencoded")
	introspectionRes, err := introspectionClient.Do(introspectionReq)
	if err != nil {
		introspectLogger.Errorf("tyk cannot connect to the authorization server %s\n", err.Error())
		writeInternalServerError(w)
		return
	}
	if introspectionRes.StatusCode == http.StatusUnauthorized {
		// If the protected resource uses OAuth 2.0 client credentials to
		//   authenticate to the introspection endpoint and its credentials are
		//   invalid, the authorization server responds with an HTTP 401
		//   (Unauthorized) as described in Section 5.2 of OAuth 2.0 [RFC6749].
		// If the protected resource uses an OAuth 2.0 bearer token to authorize
		//   its call to the introspection endpoint and the token used for
		//   authorization does not contain sufficient privileges or is otherwise
		//   invalid for this request, the authorization server responds with an
		//   HTTP 401 code as described in Section 3 of OAuth 2.0 Bearer Token
		//   Usage [RFC6750].
		introspectLogger.Errorf("tyk is not authorized to perform introspection")
		writeInternalServerError(w)
		return
	}
	defer introspectionRes.Body.Close()

	body, err := ioutil.ReadAll(introspectionRes.Body)
	if err != nil {
		introspectLogger.Errorf("unable to read response body from authorization server %s", err.Error())
		writeInternalServerError(w)
		return
	}

	irObj := &IntrospectResponse{}
	err = json.Unmarshal(body, irObj)
	if err != nil {
		introspectLogger.Errorf("unable to read json response from authorization server %s", err.Error())
		writeInternalServerError(w)
		return
	}
	if irObj.Active == false {
		// If the introspection call is properly authorized but the token is not
		//   active, does not exist on this server, or the protected resource is
		//   not allowed to introspect this particular token, then the
		//   authorization server MUST return an introspection response with the
		//   "active" field set to "false".  Note that to avoid disclosing too
		//   much of the authorization server's state to a third party, the
		//   authorization server SHOULD NOT include any additional information
		//   about an inactive token, including why the token is inactive.
		introspectLogger.Debug("access_token is inactive")
		writeUnauthorized(w)
		return
	}

	// whilst we are here - let's get the scopes and inject them into the request context
	// they may be useful later
	if irObj.Scope != nil {
		r.Header.Set("X-Tyk-Plugin-OAuth2Introspect-Scope", *irObj.Scope)
	}

	// strip the access token
	r.Header.Del(authorizationHeaderName)
}

func accessTokenFromRequest(r *http.Request) string {
	auth := r.Header.Get(authorizationHeaderName)
	split := strings.SplitN(auth, " ", 2)
	if len(split) != 2 || !strings.EqualFold(split[0], "bearer") {
		// Nothing in Authorization header, try access_token
		// Empty string returned if there's no such parameter
		if err := r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
			return ""
		}
		return r.Form.Get("access_token")
	}

	return split[1]
}

func writeUnauthorized(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
}

func writeInternalServerError(w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
}

func main() {}
