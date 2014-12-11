package main

/*
	NOTE: Requires the test tyk.conf to be in place and the settings to b correct - ugly, I know, but necessary for the end to end to work correctly.
*/

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/justinas/alice"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

const (
	T_REDIRECT_URI string = "http://client.oauth.com"
	T_CLIENT_ID    string = "1234"
)

var keyRules = `
{     "last_check": 1402492859,     "org_id": "53ac07777cbb8c2d53000002",     "allowance": 0,     "rate": 1,     "per": 1,     "expires": 0,     "quota_max": -1,     "quota_renews": 1399567002,     "quota_remaining": 10,     "quota_renewal_rate": 300 }
`

var oauthDefinition string = `
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
				"refresh_token"
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
					"name": "efault",
					"expires": "3000-01-02 15:04"
				}
			}
		},
		"proxy": {
			"listen_path": "/APIID/",
			"target_url": "http://lonelycode.com",
			"strip_listen_path": false
		}
	}
`

func createOauthAppDefinition() APISpec {
	return createDefinitionFromString(oauthDefinition)
}

func getOAuthChain(spec APISpec, Muxer *http.ServeMux) {
	// Ensure all the correct ahndlers are in place
	loadAPIEndpoints(Muxer)
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
spec.Init(&redisStore, &redisStore, healthStore)
	addOAuthHandlers(&spec, Muxer, true)
	remote, _ := url.Parse("http://lonelycode.com/")
	proxy := TykNewSingleHostReverseProxy(remote)
	proxyHandler := http.HandlerFunc(ProxyHandler(proxy, spec))
	tykMiddleware := TykMiddleware{spec, proxy}
	chain := alice.New(
		CreateMiddleware(&VersionCheck{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&Oauth2KeyExists{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&KeyExpired{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&AccessRightsCheck{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&RateLimitAndQuotaCheck{tykMiddleware}, tykMiddleware)).Then(proxyHandler)

	Muxer.Handle(spec.Proxy.ListenPath, chain)
}

func TestAuthCodeRedirect(t *testing.T) {
	thisSpec := createOauthAppDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	thisSpec.Init(&redisStore, &redisStore, healthStore)
	testMuxer := http.NewServeMux()
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

func TestAPIClientAuthorizeAuthCode(t *testing.T) {
	thisSpec := createOauthAppDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	thisSpec.Init(&redisStore, &redisStore, healthStore)
	testMuxer := http.NewServeMux()
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
	thisSpec.Init(&redisStore, &redisStore, healthStore)
	testMuxer := http.NewServeMux()
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

func GetAuthCode() map[string]string {
	thisSpec := createOauthAppDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	thisSpec.Init(&redisStore, &redisStore, healthStore)
	testMuxer := http.NewServeMux()
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
	err := json.Unmarshal(body, &thisResponse)
	if err != nil {
		fmt.Println(err)
	}

	return thisResponse
}

type tokenData struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func GetToken() tokenData {
	authData := GetAuthCode()

	thisSpec := createOauthAppDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	thisSpec.Init(&redisStore, &redisStore, healthStore)
	testMuxer := http.NewServeMux()
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
	err := json.Unmarshal(body, &thisResponse)
	if err != nil {
		fmt.Println(err)
	}

	return thisResponse
}

func TestClientAccessRequest(t *testing.T) {

	authData := GetAuthCode()

	thisSpec := createOauthAppDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	thisSpec.Init(&redisStore, &redisStore, healthStore)
	testMuxer := http.NewServeMux()
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

func TestClientRefreshRequest(t *testing.T) {

	tokenData := GetToken()

	thisSpec := createOauthAppDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	thisSpec.Init(&redisStore, &redisStore, healthStore)
	testMuxer := http.NewServeMux()
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
