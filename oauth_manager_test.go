package main

/*
	NOTE: Requires the test tyk.conf to be in place and the settings to b correct - ugly, I know, but necessary for the end to end to work correctly.
*/

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/justinas/alice"

	"fmt"

	"net/http"

	"time"

	"github.com/google/uuid"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/user"
)

const (
	authRedirectUri  = "http://client.oauth.com"
	authRedirectUri2 = "http://client2.oauth.com"
	authClientID     = "1234"
	authClientSecret = "aabbccdd"
)

const keyRules = `{
	"last_check": 1402492859,
	"org_id": "53ac07777cbb8c2d53000002",
	"rate": 1,
	"per": 1,
	"quota_max": -1,
	"quota_renews": 1399567002,
	"quota_remaining": 10,
	"quota_renewal_rate": 300
}`

const oauthDefinition = `{
	"api_id": "999999",
	"org_id": "default",
	"auth": {"auth_header_name": "authorization"},
	"use_oauth2": true,
	"oauth_meta": {
		"allowed_access_types": [
			"authorization_code",
			"refresh_token",
			"client_credentials"
		],
		"allowed_authorize_types": [
			"code",
			"token"
		],
		"auth_login_redirect": "` + testHttpPost + `"
	},
	"notifications": {
		"shared_secret": "9878767657654343123434556564444",
		"oauth_on_keychange_url": "` + testHttpPost + `"
	},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/APIID/",
		"target_url": "` + testHttpAny + `"
	}
}`

func getOAuthChain(spec *APISpec, muxer *mux.Router, clientID string) {
	// Ensure all the correct ahndlers are in place
	loadAPIEndpoints(muxer)
	spec.OAuthManager = addOAuthHandlers(spec, muxer)

	// add a test client
	testPolicy := user.Policy{}
	testPolicy.Rate = 100
	testPolicy.Per = 1
	testPolicy.QuotaMax = -1
	testPolicy.QuotaRenewalRate = 1000000000

	policiesMu.Lock()
	policiesByID["TEST-4321"] = testPolicy
	policiesMu.Unlock()

	var redirectURI string
	// If separator is not set that means multiple redirect uris not supported
	if config.Global.OauthRedirectUriSeparator == "" {
		redirectURI = "http://client.oauth.com"

		// If separator config is set that means multiple redirect uris are supported
	} else {
		redirectURI = strings.Join([]string{"http://client.oauth.com", "http://client2.oauth.com", "http://client3.oauth.com"}, config.Global.OauthRedirectUriSeparator)
	}
	testClient := OAuthClient{
		ClientID:          clientID,
		ClientSecret:      authClientSecret,
		ClientRedirectURI: redirectURI,
		PolicyID:          "TEST-4321",
	}
	spec.OAuthManager.OsinServer.Storage.SetClient(testClient.ClientID, &testClient, false)

	remote, _ := url.Parse(testHttpAny)
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	proxyHandler := ProxyHandler(proxy, spec)
	baseMid := BaseMiddleware{spec, proxy}
	chain := alice.New(mwList(
		&VersionCheck{BaseMiddleware: baseMid},
		&Oauth2KeyExists{baseMid},
		&KeyExpired{baseMid},
		&AccessRightsCheck{baseMid},
		&RateLimitAndQuotaCheck{baseMid},
	)...).Then(proxyHandler)
	muxer.Handle(spec.Proxy.ListenPath, chain)
}

func TestAuthCodeRedirect(t *testing.T) {
	spec := createSpecTest(t, oauthDefinition)
	testMuxer := mux.NewRouter()
	getOAuthChain(spec, testMuxer, authClientID)

	uri := "/APIID/oauth/authorize/"

	param := make(url.Values)
	param.Set("response_type", "code")
	param.Set("redirect_uri", authRedirectUri)
	param.Set("client_id", authClientID)
	req := testReq(t, "POST", uri, param.Encode())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	if recorder.Code != 307 {
		t.Error("Request should have redirected, code should have been 307 but is: ", recorder.Code)
		t.Error(recorder.Body)
		t.Error(req.Body)
	}
}

func TestAuthCodeRedirectMultipleURL(t *testing.T) {
	// Enable multiple Redirect URIs
	config.Global.OauthRedirectUriSeparator = ","

	spec := createSpecTest(t, oauthDefinition)
	testMuxer := mux.NewRouter()
	getOAuthChain(spec, testMuxer, authClientID)

	uri := "/APIID/oauth/authorize/"

	param := make(url.Values)
	param.Set("response_type", "code")
	param.Set("redirect_uri", authRedirectUri2)
	param.Set("client_id", authClientID)
	req := testReq(t, "POST", uri, param.Encode())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	if recorder.Code != 307 {
		t.Error("Request should have redirected, code should have been 307 but is: ", recorder.Code)
		t.Error(recorder.Body)
		t.Error(req.Body)
	}
}

func TestAuthCodeRedirectInvalidMultipleURL(t *testing.T) {
	// Disable multiple Redirect URIs
	config.Global.OauthRedirectUriSeparator = ""

	spec := createSpecTest(t, oauthDefinition)
	testMuxer := mux.NewRouter()
	getOAuthChain(spec, testMuxer, authClientID)

	uri := "/APIID/oauth/authorize/"

	param := make(url.Values)
	param.Set("response_type", "code")
	param.Set("redirect_uri", authRedirectUri2)
	param.Set("client_id", authClientID)
	req := testReq(t, "POST", uri, param.Encode())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	if recorder.Code == 307 {
		t.Error("Request should have not been redirected, code should have been 403 but is: ", recorder.Code)
		t.Error(recorder.Body)
		t.Error(req.Body)
	}
}

func TestAPIClientAuthorizeAuthCode(t *testing.T) {
	spec := createSpecTest(t, oauthDefinition)
	testMuxer := mux.NewRouter()
	getOAuthChain(spec, testMuxer, authClientID)

	uri := "/APIID/tyk/oauth/authorize-client/"

	param := make(url.Values)
	param.Set("response_type", "code")
	param.Set("redirect_uri", authRedirectUri)
	param.Set("client_id", authClientID)
	param.Set("key_rules", keyRules)
	req := withAuth(testReq(t, "POST", uri, param.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Response code should have been 200 but is: ", recorder.Code)
		t.Error(recorder.Body)
		t.Error(req.Body)
	}
}

func TestAPIClientAuthorizeToken(t *testing.T) {
	spec := createSpecTest(t, oauthDefinition)
	testMuxer := mux.NewRouter()
	getOAuthChain(spec, testMuxer, authClientID)

	uri := "/APIID/tyk/oauth/authorize-client/"

	param := make(url.Values)
	param.Set("response_type", "token")
	param.Set("redirect_uri", authRedirectUri)
	param.Set("client_id", authClientID)
	param.Set("key_rules", keyRules)
	req := withAuth(testReq(t, "POST", uri, param.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Response code should have been 200 but is: ", recorder.Code)
		t.Error(recorder.Body)
		t.Error(req.Body)
	}
}

func TestAPIClientAuthorizeTokenWithPolicy(t *testing.T) {
	spec := createSpecTest(t, oauthDefinition)
	testMuxer := mux.NewRouter()
	getOAuthChain(spec, testMuxer, authClientID)

	uri := "/APIID/tyk/oauth/authorize-client/"

	param := make(url.Values)
	param.Set("response_type", "token")
	param.Set("redirect_uri", authRedirectUri)
	param.Set("client_id", authClientID)

	req := withAuth(testReq(t, "POST", uri, param.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Response code should have been 200 but is: ", recorder.Code)
		t.Error(recorder.Body)
		t.Error(req.Body)
	}

	asData := make(map[string]interface{})
	if err := json.NewDecoder(recorder.Body).Decode(&asData); err != nil {
		t.Fatal("Decode failed:", err)
	}
	token, ok := asData["access_token"].(string)
	if !ok {
		t.Fatal("No access token found")
	}

	// Verify the token is correct
	session, ok := spec.AuthManager.KeyAuthorised(token)
	if !ok {
		t.Error("Key was not created (Can't find it)!")
	}

	if !reflect.DeepEqual(session.PolicyIDs(), []string{"TEST-4321"}) {
		t.Error("Policy not added to token!")
	}
}

func getAuthCode(t *testing.T) map[string]string {
	spec := createSpecTest(t, oauthDefinition)
	testMuxer := mux.NewRouter()
	getOAuthChain(spec, testMuxer, authClientID)

	uri := "/APIID/tyk/oauth/authorize-client/"

	param := make(url.Values)
	param.Set("response_type", "code")
	param.Set("redirect_uri", authRedirectUri)
	param.Set("client_id", authClientID)
	param.Set("key_rules", keyRules)
	req := withAuth(testReq(t, "POST", uri, param.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	response := map[string]string{}
	json.NewDecoder(recorder.Body).Decode(&response)
	return response
}

func TestGetClientTokens(t *testing.T) {
	clientID := uuid.New().String()

	spec := createSpecTest(t, oauthDefinition)
	testMuxer := mux.NewRouter()
	getOAuthChain(spec, testMuxer, clientID)

	apisMu.Lock()
	apisByID["999999"] = spec
	apisMu.Unlock()

	// set tokens to be expired after 1 second
	config.Global.OauthTokenExpire = 1
	// cleanup tokens older than 3 seconds
	config.Global.OauthTokenExpiredRetainPeriod = 3

	uri := "/APIID/tyk/oauth/authorize-client/"

	// make three tokens
	param := make(url.Values)
	param.Set("response_type", "token")
	param.Set("redirect_uri", authRedirectUri)
	param.Set("client_id", clientID)
	param.Set("client_secret", authClientSecret)
	param.Set("key_rules", keyRules)
	tokensID := map[string]bool{}
	for i := 0; i < 3; i++ {
		req := withAuth(testReq(t, "POST", uri, param.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		recorder := httptest.NewRecorder()
		testMuxer.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			t.Error("Token wasn't created. Response code:", recorder.Code)
		}

		response := map[string]interface{}{}
		if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
			t.Fatal(err)
		}
		tokensID[response["access_token"].(string)] = true
	}

	// get list of tokens
	listURI := fmt.Sprintf("/tyk/oauth/clients/999999/%s/tokens", clientID)
	req := withAuth(testReq(t, "GET", listURI, nil))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Error("Token list wasn't received. Response code:", recorder.Code)
	}

	tokensResp := []OAuthClientToken{}
	if err := json.NewDecoder(recorder.Body).Decode(&tokensResp); err != nil {
		t.Fatal(err)
	}

	// check response
	if len(tokensResp) != len(tokensID) {
		t.Errorf("Wrong number of tokens received. Expected: %d. Got: %d", len(tokensID), len(tokensResp))
	}
	for _, token := range tokensResp {
		if !tokensID[token.Token] {
			t.Errorf("Token %s is not found in expected result. Expecting: %v", token.Token, tokensID)
		}
	}

	// sleep to wait until tokens expire
	time.Sleep(2 * time.Second)

	// get tokens again
	recorder = httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Error("Token list wasn't received. Response code:", recorder.Code)
	}
	tokensResp = []OAuthClientToken{}
	if err := json.NewDecoder(recorder.Body).Decode(&tokensResp); err != nil {
		t.Fatal(err)
	}
	if len(tokensResp) > 0 {
		t.Errorf("Wrong number of tokens received. Expected 0 - all tokens expired. Got: %d", len(tokensResp))
	}
}

type tokenData struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func getToken(t *testing.T) tokenData {
	authData := getAuthCode(t)

	spec := createSpecTest(t, oauthDefinition)
	testMuxer := mux.NewRouter()
	getOAuthChain(spec, testMuxer, authClientID)

	uri := "/APIID/oauth/token/"

	param := make(url.Values)
	param.Set("grant_type", "authorization_code")
	param.Set("redirect_uri", authRedirectUri)
	param.Set("client_id", authClientID)
	param.Set("code", authData["code"])
	req := testReq(t, "POST", uri, param.Encode())
	req.Header.Set("Authorization", "Basic MTIzNDphYWJiY2NkZA==")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	response := tokenData{}
	json.NewDecoder(recorder.Body).Decode(&response)
	return response
}

func TestOAuthClientCredsGrant(t *testing.T) {
	spec := createSpecTest(t, oauthDefinition)
	testMuxer := mux.NewRouter()
	getOAuthChain(spec, testMuxer, authClientID)

	uri := "/APIID/oauth/token/"

	param := make(url.Values)
	param.Set("grant_type", "client_credentials")
	param.Set("client_id", authClientID)
	param.Set("client_secret", authClientSecret)

	req := testReq(t, "POST", uri, param.Encode())
	req.Header.Set("Authorization", "Basic MTIzNDphYWJiY2NkZA==")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	response := tokenData{}
	json.NewDecoder(recorder.Body).Decode(&response)

	if recorder.Code != 200 {
		t.Error("Response code should have 200 error but is: ", recorder.Code)
		t.Error(recorder.Body)
		t.Error(req.Body)
	}

	if response.AccessToken == "" {
		t.Error("Access token is empty!")
		t.Error(recorder.Body)
		t.Error(req.Body)
	}

}

func TestClientAccessRequest(t *testing.T) {

	authData := getAuthCode(t)

	spec := createSpecTest(t, oauthDefinition)
	testMuxer := mux.NewRouter()
	getOAuthChain(spec, testMuxer, authClientID)

	uri := "/APIID/oauth/token/"

	param := make(url.Values)
	param.Set("grant_type", "authorization_code")
	param.Set("redirect_uri", authRedirectUri)
	param.Set("client_id", authClientID)
	param.Set("code", authData["code"])
	req := testReq(t, "POST", uri, param.Encode())
	req.Header.Set("Authorization", "Basic MTIzNDphYWJiY2NkZA==")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Response code should have been 200 but is: ", recorder.Code)
		t.Error(recorder.Body)
		t.Error(req.Body)
		t.Error("CODE: ", authData)
	}
}

func TestOAuthAPIRefreshInvalidate(t *testing.T) {

	// Step 1 create token
	tokenData := getToken(t)

	spec := createSpecTest(t, oauthDefinition)
	loadApps([]*APISpec{spec}, discardMuxer)
	testMuxer := mux.NewRouter()
	getOAuthChain(spec, testMuxer, authClientID)

	// Step 2 - invalidate the refresh token

	uri1 := "/tyk/oauth/refresh/" + tokenData.RefreshToken + "?"

	recorder := httptest.NewRecorder()
	param1 := make(url.Values)
	//MakeSampleAPI()
	param1.Set("api_id", "999999")
	req := withAuth(testReq(t, "DELETE", uri1+param1.Encode(), nil))

	testMuxer.ServeHTTP(recorder, req)

	newSuccess := apiModifyKeySuccess{}
	json.NewDecoder(recorder.Body).Decode(&newSuccess)

	if newSuccess.Status != "ok" {
		t.Error("key not deleted, status error:\n", recorder.Body.String())
		t.Error(apisByID)
	}
	if newSuccess.Action != "deleted" {
		t.Error("Response is incorrect - action is not 'deleted' :\n", recorder.Body.String())
	}

	// Step 3 - try to refresh

	uri := "/APIID/oauth/token/"

	param := make(url.Values)
	param.Set("grant_type", "refresh_token")
	param.Set("redirect_uri", authRedirectUri)
	param.Set("client_id", authClientID)
	param.Set("refresh_token", tokenData.RefreshToken)
	req = testReq(t, "POST", uri, param.Encode())
	req.Header.Set("Authorization", "Basic MTIzNDphYWJiY2NkZA==")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder = httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Response code should have been error but is: ", recorder.Code)
		t.Error(recorder.Body)
		t.Error(req.Body)
		t.Error("CODE: ", tokenData.RefreshToken)
	}
}

func TestClientRefreshRequest(t *testing.T) {

	tokenData := getToken(t)

	spec := createSpecTest(t, oauthDefinition)
	testMuxer := mux.NewRouter()
	getOAuthChain(spec, testMuxer, authClientID)

	uri := "/APIID/oauth/token/"

	param := make(url.Values)
	param.Set("grant_type", "refresh_token")
	param.Set("redirect_uri", authRedirectUri)
	param.Set("client_id", authClientID)
	param.Set("refresh_token", tokenData.RefreshToken)
	req := testReq(t, "POST", uri, param.Encode())
	req.Header.Set("Authorization", "Basic MTIzNDphYWJiY2NkZA==")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Response code should have been 200 but is: ", recorder.Code)
		t.Error(recorder.Body)
		t.Error(req.Body)
		t.Error("CODE: ", tokenData.RefreshToken)
	}
}

func TestClientRefreshRequestDouble(t *testing.T) {

	tokenData := getToken(t)

	spec := createSpecTest(t, oauthDefinition)
	testMuxer := mux.NewRouter()
	getOAuthChain(spec, testMuxer, authClientID)

	uri := "/APIID/oauth/token/"

	// req 1
	param := make(url.Values)
	param.Set("grant_type", "refresh_token")
	param.Set("redirect_uri", authRedirectUri)
	param.Set("client_id", authClientID)
	param.Set("refresh_token", tokenData.RefreshToken)
	req := testReq(t, "POST", uri, param.Encode())
	req.Header.Set("Authorization", "Basic MTIzNDphYWJiY2NkZA==")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	responseData := make(map[string]interface{})

	json.NewDecoder(recorder.Body).Decode(&responseData)
	token, ok := responseData["refresh_token"].(string)
	if !ok {
		t.Fatal("No refresh token found")
	}

	param2 := make(url.Values)
	param2.Set("grant_type", "refresh_token")
	param2.Set("redirect_uri", authRedirectUri)
	param2.Set("client_id", authClientID)
	param2.Set("refresh_token", token)
	req = testReq(t, "POST", uri, param2.Encode())
	req.Header.Set("Authorization", "Basic MTIzNDphYWJiY2NkZA==")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder2 := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder2, req)

	if recorder2.Code != 200 {
		t.Error("Response code should have been 200 but is: ", recorder2.Code)
		t.Error(recorder2.Body)
		t.Error(req.Body)
	}

}
