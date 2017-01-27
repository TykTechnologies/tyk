package main

/*
	NOTE: Requires the test tyk.conf to be in place and the settings to b correct - ugly, I know, but necessary for the end to end to work correctly.
*/

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/justinas/alice"
)

const (
	T_REDIRECT_URI  = "http://client.oauth.com"
	T_REDIRECT_URI2 = "http://client2.oauth.com"
	T_CLIENT_ID     = "1234"
	T_CLIENT_SECRET = "aabbccdd"
)

var keyRules = `
{     "last_check": 1402492859,     "org_id": "53ac07777cbb8c2d53000002",     "allowance": 0,     "rate": 1,     "per": 1,     "expires": 0,     "quota_max": -1,     "quota_renews": 1399567002,     "quota_remaining": 10,     "quota_renewal_rate": 300 }
`

var oauthDefinition = `
	{
		"name": "OAUTH Test API",
		"api_id": "999999",
		"org_id": "default",
		"definition": {
			"location": "header",
			"key": "version"
		},
		"auth": {
			"auth_header_name": "authorization"
		},
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
			"auth_login_redirect": "http://posttestserver.com/post.php?dir=gateway_authorization"
		},
		"notifications": {
			"shared_secret": "9878767657654343123434556564444",
			"oauth_on_keychange_url": "http://posttestserver.com/post.php?dir=oauth_notifications"
		},
		"version_data": {
			"not_versioned": true,
			"versions": {
				"Default": {
					"name": "Default",
					"use_extended_paths": true,
					"expires": "3000-01-02 15:04"
				}
			}
		},
		"proxy": {
			"listen_path": "/APIID/",
			"target_url": "http://example.com",
			"strip_listen_path": false
		}
	}
`

func createOauthAppDefinition() *APISpec {
	return createDefinitionFromString(oauthDefinition)
}

func getOAuthChain(spec *APISpec, Muxer *mux.Router) {
	// Ensure all the correct ahndlers are in place
	loadAPIEndpoints(Muxer)
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	addOAuthHandlers(spec, Muxer, true)
	remote, _ := url.Parse("http://example.com/")
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	proxyHandler := http.HandlerFunc(ProxyHandler(proxy, spec))
	tykMiddleware := &TykMiddleware{spec, proxy}
	chain := alice.New(
		CreateMiddleware(&VersionCheck{TykMiddleware: tykMiddleware}, tykMiddleware),
		CreateMiddleware(&Oauth2KeyExists{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&KeyExpired{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&AccessRightsCheck{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&RateLimitAndQuotaCheck{tykMiddleware}, tykMiddleware)).Then(proxyHandler)

	//ApiSpecRegister[spec.APIID] = spec
	Muxer.Handle(spec.Proxy.ListenPath, chain)
}

func makeOAuthAPI() *APISpec {
	log.Debug("CREATING TEMPORARY API FOR OAUTH")
	thisSpec := createOauthAppDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	thisSpec.Init(&redisStore, &redisStore, healthStore, orgStore)

	specs := &[]*APISpec{thisSpec}
	newMuxes := mux.NewRouter()
	loadAPIEndpoints(newMuxes)
	loadApps(specs, newMuxes)

	newHttpMux := http.NewServeMux()
	newHttpMux.Handle("/", newMuxes)
	http.DefaultServeMux = newHttpMux

	log.Debug("OAUTH Test Reload complete")

	return thisSpec
}

func TestAuthCodeRedirect(t *testing.T) {
	thisSpec := createOauthAppDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	thisSpec.Init(&redisStore, &redisStore, healthStore, orgStore)
	testMuxer := mux.NewRouter()
	getOAuthChain(thisSpec, testMuxer)

	uri := "/APIID/oauth/authorize/"
	method := "POST"

	param := make(url.Values)
	param.Set("response_type", "code")
	param.Set("redirect_uri", T_REDIRECT_URI)
	param.Set("client_id", T_CLIENT_ID)
	req, err := http.NewRequest(method, uri, bytes.NewBufferString(param.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		t.Fatal(err)
	}

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
	config.OauthRedirectUriSeparator = ","

	thisSpec := createOauthAppDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	thisSpec.Init(&redisStore, &redisStore, healthStore, orgStore)
	testMuxer := mux.NewRouter()
	getOAuthChain(thisSpec, testMuxer)

	uri := "/APIID/oauth/authorize/"
	method := "POST"

	param := make(url.Values)
	param.Set("response_type", "code")
	param.Set("redirect_uri", T_REDIRECT_URI2)
	param.Set("client_id", T_CLIENT_ID)
	req, err := http.NewRequest(method, uri, bytes.NewBufferString(param.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		t.Fatal(err)
	}

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
	config.OauthRedirectUriSeparator = ""

	thisSpec := createOauthAppDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	thisSpec.Init(&redisStore, &redisStore, healthStore, orgStore)
	testMuxer := mux.NewRouter()
	getOAuthChain(thisSpec, testMuxer)

	uri := "/APIID/oauth/authorize/"
	method := "POST"

	param := make(url.Values)
	param.Set("response_type", "code")
	param.Set("redirect_uri", T_REDIRECT_URI2)
	param.Set("client_id", T_CLIENT_ID)
	req, err := http.NewRequest(method, uri, bytes.NewBufferString(param.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	if recorder.Code == 307 {
		t.Error("Request should have not been redirected, code should have been 403 but is: ", recorder.Code)
		t.Error(recorder.Body)
		t.Error(req.Body)
	}
}

func TestAPIClientAuthorizeAuthCode(t *testing.T) {
	thisSpec := createOauthAppDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	thisSpec.Init(&redisStore, &redisStore, healthStore, orgStore)
	testMuxer := mux.NewRouter()
	getOAuthChain(thisSpec, testMuxer)

	uri := "/APIID/tyk/oauth/authorize-client/"
	method := "POST"

	param := make(url.Values)
	param.Set("response_type", "code")
	param.Set("redirect_uri", T_REDIRECT_URI)
	param.Set("client_id", T_CLIENT_ID)
	param.Set("key_rules", keyRules)
	req, err := http.NewRequest(method, uri, bytes.NewBufferString(param.Encode()))
	req.Header.Set("x-tyk-authorization", "352d20ee67be67f6340b4c0605b044b7")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Response code should have been 200 but is: ", recorder.Code)
		t.Error(recorder.Body)
		t.Error(req.Body)
	}
}

func TestAPIClientAuthorizeToken(t *testing.T) {
	thisSpec := createOauthAppDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	thisSpec.Init(&redisStore, &redisStore, healthStore, orgStore)
	testMuxer := mux.NewRouter()
	getOAuthChain(thisSpec, testMuxer)

	uri := "/APIID/tyk/oauth/authorize-client/"
	method := "POST"

	param := make(url.Values)
	param.Set("response_type", "token")
	param.Set("redirect_uri", T_REDIRECT_URI)
	param.Set("client_id", T_CLIENT_ID)
	param.Set("key_rules", keyRules)
	req, err := http.NewRequest(method, uri, bytes.NewBufferString(param.Encode()))
	req.Header.Set("x-tyk-authorization", "352d20ee67be67f6340b4c0605b044b7")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Response code should have been 200 but is: ", recorder.Code)
		t.Error(recorder.Body)
		t.Error(req.Body)
	}
}

func TestAPIClientAuthorizeTokenWithPolicy(t *testing.T) {
	thisSpec := createOauthAppDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	thisSpec.Init(&redisStore, &redisStore, healthStore, orgStore)
	testMuxer := mux.NewRouter()
	getOAuthChain(thisSpec, testMuxer)

	uri := "/APIID/tyk/oauth/authorize-client/"
	method := "POST"

	param := make(url.Values)
	param.Set("response_type", "token")
	param.Set("redirect_uri", T_REDIRECT_URI)
	param.Set("client_id", T_CLIENT_ID)

	req, err := http.NewRequest(method, uri, bytes.NewBufferString(param.Encode()))
	req.Header.Set("x-tyk-authorization", "352d20ee67be67f6340b4c0605b044b7")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Response code should have been 200 but is: ", recorder.Code)
		t.Error(recorder.Body)
		t.Error(req.Body)
	}

	asData := make(map[string]interface{})
	decoder := json.NewDecoder(recorder.Body)
	if err := decoder.Decode(&asData); err != nil {
		t.Fatal("Decode failed:", err)
	}
	token, ok := asData["access_token"].(string)
	if !ok {
		t.Fatal("No access token found")
	}

	// Verify the token is correct
	key, fnd := redisStore.GetKey(token)
	if fnd != nil {
		t.Error("Key was not created (Can't find it)!")
		fmt.Println(fnd)
	}

	if !strings.Contains(key, `"apply_policy_id":"TEST-4321"`) {
		t.Error("Policy not added to token!")
		fmt.Println(key)
	}
}

func getAuthCode() map[string]string {
	thisSpec := createOauthAppDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	thisSpec.Init(&redisStore, &redisStore, healthStore, orgStore)
	testMuxer := mux.NewRouter()
	getOAuthChain(thisSpec, testMuxer)

	uri := "/APIID/tyk/oauth/authorize-client/"
	method := "POST"

	param := make(url.Values)
	param.Set("response_type", "code")
	param.Set("redirect_uri", T_REDIRECT_URI)
	param.Set("client_id", T_CLIENT_ID)
	param.Set("key_rules", keyRules)
	req, _ := http.NewRequest(method, uri, bytes.NewBufferString(param.Encode()))
	req.Header.Set("x-tyk-authorization", "352d20ee67be67f6340b4c0605b044b7")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	var thisResponse = map[string]string{}
	body, _ := ioutil.ReadAll(recorder.Body)
	if err := json.Unmarshal(body, &thisResponse); err != nil {
		fmt.Println(err)
	}

	return thisResponse
}

type tokenData struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func getToken() tokenData {
	authData := getAuthCode()

	thisSpec := createOauthAppDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	thisSpec.Init(&redisStore, &redisStore, healthStore, orgStore)
	testMuxer := mux.NewRouter()
	getOAuthChain(thisSpec, testMuxer)

	uri := "/APIID/oauth/token/"
	method := "POST"

	param := make(url.Values)
	param.Set("grant_type", "authorization_code")
	param.Set("redirect_uri", T_REDIRECT_URI)
	param.Set("client_id", T_CLIENT_ID)
	param.Set("code", authData["code"])
	req, _ := http.NewRequest(method, uri, bytes.NewBufferString(param.Encode()))
	req.Header.Set("Authorization", "Basic MTIzNDphYWJiY2NkZA==")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	var thisResponse = tokenData{}
	body, _ := ioutil.ReadAll(recorder.Body)
	//	fmt.Println(string(body))
	if err := json.Unmarshal(body, &thisResponse); err != nil {
		fmt.Println(err)
	}
	log.Debug("TOKEN DATA: ", string(body))
	return thisResponse
}

func TestOAuthClientCredsGrant(t *testing.T) {
	thisSpec := createOauthAppDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	thisSpec.Init(&redisStore, &redisStore, healthStore, orgStore)
	testMuxer := mux.NewRouter()
	getOAuthChain(thisSpec, testMuxer)

	uri := "/APIID/oauth/token/"
	method := "POST"

	param := make(url.Values)
	param.Set("grant_type", "client_credentials")
	param.Set("client_id", T_CLIENT_ID)
	param.Set("client_secret", T_CLIENT_SECRET)

	req, _ := http.NewRequest(method, uri, bytes.NewBufferString(param.Encode()))
	req.Header.Set("Authorization", "Basic MTIzNDphYWJiY2NkZA==")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	var thisResponse = tokenData{}
	body, _ := ioutil.ReadAll(recorder.Body)
	//	fmt.Println(string(body))
	err := json.Unmarshal(body, &thisResponse)
	if err != nil {
		fmt.Println(err)
	}
	log.Debug("TOKEN DATA: ", string(body))
	log.Info("Access token: ", thisResponse.AccessToken)

	if recorder.Code != 200 {
		t.Error("Response code should have 200 error but is: ", recorder.Code)
		t.Error(recorder.Body)
		t.Error(req.Body)
	}

	if thisResponse.AccessToken == "" {
		t.Error("Access token is empty!")
		t.Error(recorder.Body)
		t.Error(req.Body)
	}

}

func TestClientAccessRequest(t *testing.T) {

	authData := getAuthCode()

	thisSpec := createOauthAppDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	thisSpec.Init(&redisStore, &redisStore, healthStore, orgStore)
	testMuxer := mux.NewRouter()
	getOAuthChain(thisSpec, testMuxer)

	uri := "/APIID/oauth/token/"
	method := "POST"

	param := make(url.Values)
	param.Set("grant_type", "authorization_code")
	param.Set("redirect_uri", T_REDIRECT_URI)
	param.Set("client_id", T_CLIENT_ID)
	param.Set("code", authData["code"])
	req, err := http.NewRequest(method, uri, bytes.NewBufferString(param.Encode()))
	req.Header.Set("Authorization", "Basic MTIzNDphYWJiY2NkZA==")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		t.Fatal(err)
	}

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
	tokenData := getToken()

	// thisSpec := createOauthAppDefinition()

	thisSpec := makeOAuthAPI()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	thisSpec.Init(&redisStore, &redisStore, healthStore, orgStore)
	testMuxer := mux.NewRouter()
	getOAuthChain(thisSpec, testMuxer)
	log.Warning("Created OAUTH API with APIID: ", thisSpec.APIID)
	log.Warning("SPEC REGISTER: ", ApiSpecRegister)

	// Step 2 - invalidate the refresh token

	uri1 := "/tyk/oauth/refresh/" + tokenData.RefreshToken + "?"
	method1 := "DELETE"

	recorder1 := httptest.NewRecorder()
	param1 := make(url.Values)
	//MakeSampleAPI()
	param1.Set("api_id", "999999")
	req1, err1 := http.NewRequest(method1, uri1+param1.Encode(), nil)

	if err1 != nil {
		t.Fatal(err1)
	}

	req1.Header.Add("x-tyk-authorization", "352d20ee67be67f6340b4c0605b044b7")

	testMuxer.ServeHTTP(recorder1, req1)

	newSuccess := Success{}
	err := json.Unmarshal([]byte(recorder1.Body.String()), &newSuccess)

	if err != nil {
		t.Error("Could not unmarshal success message:\n", err)
		t.Error(recorder1.Body.String())
	} else {
		if newSuccess.Status != "ok" {
			t.Error("key not deleted, status error:\n", recorder1.Body.String())
			t.Error(ApiSpecRegister)
		}
		if newSuccess.Action != "deleted" {
			t.Error("Response is incorrect - action is not 'deleted' :\n", recorder1.Body.String())
		}
	}

	// Step 3 - try to refresh

	uri := "/APIID/oauth/token/"
	method := "POST"

	param := make(url.Values)
	param.Set("grant_type", "refresh_token")
	param.Set("redirect_uri", T_REDIRECT_URI)
	param.Set("client_id", T_CLIENT_ID)
	param.Set("refresh_token", tokenData.RefreshToken)
	req, err := http.NewRequest(method, uri, bytes.NewBufferString(param.Encode()))
	req.Header.Set("Authorization", "Basic MTIzNDphYWJiY2NkZA==")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Response code should have been error but is: ", recorder.Code)
		t.Error(recorder.Body)
		t.Error(req.Body)
		t.Error("CODE: ", tokenData.RefreshToken)
	}
}

func TestClientRefreshRequest(t *testing.T) {

	tokenData := getToken()

	thisSpec := createOauthAppDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	thisSpec.Init(&redisStore, &redisStore, healthStore, orgStore)
	testMuxer := mux.NewRouter()
	getOAuthChain(thisSpec, testMuxer)

	uri := "/APIID/oauth/token/"
	method := "POST"

	param := make(url.Values)
	param.Set("grant_type", "refresh_token")
	param.Set("redirect_uri", T_REDIRECT_URI)
	param.Set("client_id", T_CLIENT_ID)
	param.Set("refresh_token", tokenData.RefreshToken)
	req, err := http.NewRequest(method, uri, bytes.NewBufferString(param.Encode()))
	req.Header.Set("Authorization", "Basic MTIzNDphYWJiY2NkZA==")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		t.Fatal(err)
	}

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

	tokenData := getToken()

	thisSpec := createOauthAppDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	thisSpec.Init(&redisStore, &redisStore, healthStore, orgStore)
	testMuxer := mux.NewRouter()
	getOAuthChain(thisSpec, testMuxer)

	uri := "/APIID/oauth/token/"
	method := "POST"

	// req 1
	param := make(url.Values)
	param.Set("grant_type", "refresh_token")
	param.Set("redirect_uri", T_REDIRECT_URI)
	param.Set("client_id", T_CLIENT_ID)
	param.Set("refresh_token", tokenData.RefreshToken)
	req, err := http.NewRequest(method, uri, bytes.NewBufferString(param.Encode()))
	req.Header.Set("Authorization", "Basic MTIzNDphYWJiY2NkZA==")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder, req)

	responseData := make(map[string]interface{})

	body, _ := ioutil.ReadAll(recorder.Body)
	if err := json.Unmarshal(body, &responseData); err != nil {
		t.Fatal("Decode failed:", err)
	}
	log.Debug("Refresh token body", string(body))
	token, ok := responseData["refresh_token"].(string)
	if !ok {
		t.Fatal("No refresh token found")
	}

	param2 := make(url.Values)
	param2.Set("grant_type", "refresh_token")
	param2.Set("redirect_uri", T_REDIRECT_URI)
	param2.Set("client_id", T_CLIENT_ID)
	param2.Set("refresh_token", token)
	req2, err2 := http.NewRequest(method, uri, bytes.NewBufferString(param2.Encode()))
	req2.Header.Set("Authorization", "Basic MTIzNDphYWJiY2NkZA==")
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err2 != nil {
		t.Fatal(err2)
	}

	recorder2 := httptest.NewRecorder()
	testMuxer.ServeHTTP(recorder2, req2)

	if recorder2.Code != 200 {
		t.Error("Response code should have been 200 but is: ", recorder2.Code)
		t.Error(recorder2.Body)
		t.Error(req2.Body)
	}

}
