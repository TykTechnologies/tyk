package main

/*
	NOTE: Requires the test tyk.conf to be in place and the settings to b correct - ugly, I know, but necessary for the end to end to work correctly.
 */

import (
	"github.com/RangelReale/osin"
	"testing"
	"bytes"
	"net/url"
	"net/http"
	"github.com/justinas/alice"
	"net/http/httputil"
	"net/http/httptest"
	"encoding/json"
	"io/ioutil"
	"fmt"
)

const (
	T_REDIRECT_URI string = "http://client.oauth.com"
	T_CLIENT_ID string = "1234"
)

var key_rules = `
{     "last_check": 1402492859,     "org_id": "53ac07777cbb8c2d53000002",     "allowance": 0,     "rate": 1,     "per": 1,     "expires": 0,     "quota_max": -1,     "quota_renews": 1399567002,     "quota_remaining": 10,     "quota_renewal_rate": 300 }
`

func createOauthAppDefinition() APISpec {
	var thisDef = APIDefinition{}
	var v1 = VersionInfo{}
	var thisSpec = APISpec{}
	var thisLoader = APIDefinitionLoader{}

	thisDef.Name = "OAUTH Test API"
	thisDef.APIID = "999999"
	thisDef.VersionData.NotVersioned = true
	thisDef.UseOauth2 = true

	thisDef.Oauth2Meta.AllowedAccessTypes = []osin.AccessRequestType{osin.AUTHORIZATION_CODE, osin.REFRESH_TOKEN}
	thisDef.Oauth2Meta.AllowedAuthorizeTypes = []osin.AuthorizeRequestType{osin.CODE, osin.TOKEN}

	thisDef.Proxy.ListenPath = "/APIID/"
	thisDef.Proxy.TargetURL = "http://lonelycode.com"

	v1.Name = "Default"
	v1.Expires = "2100-01-02 15:04"
	v1.Paths.Ignored = []string{}
	v1.Paths.BlackList = []string{}
	v1.Paths.WhiteList = []string{}

	thisDef.VersionData.Versions = make(map[string]VersionInfo)
	thisDef.VersionData.Versions[v1.Name] = v1

	thisSpec.APIDefinition = thisDef
	thisSpec.RxPaths = make(map[string][]URLSpec)
	thisSpec.WhiteListEnabled = make(map[string]bool)

	pathSpecs, whiteListSpecs := thisLoader.getPathSpecs(v1)
	thisSpec.RxPaths[v1.Name] = pathSpecs

	thisSpec.WhiteListEnabled[v1.Name] = whiteListSpecs

	return thisSpec
}

func getOAuthChain(spec APISpec, Muxer *http.ServeMux) {
	// Ensure all the correct ahndlers are in place
	loadAPIEndpoints(Muxer)
	addOAuthHandlers(spec, Muxer, true)
	remote, _ := url.Parse("http://lonelycode.com/")
	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxyHandler := http.HandlerFunc(ProxyHandler(proxy, spec))
	tykMiddleware := TykMiddleware{spec, proxy}
	chain := alice.New(
		VersionCheck{tykMiddleware}.New(),
		KeyExists{tykMiddleware}.New(),
		Oauth2KeyExists{tykMiddleware}.New(),
		KeyExpired{tykMiddleware}.New(),
		AccessRightsCheck{tykMiddleware}.New(),
		RateLimitAndQuotaCheck{tykMiddleware}.New()).Then(proxyHandler)

	Muxer.Handle(spec.Proxy.ListenPath, chain)
}

func TestAuthCodeRedirect(t *testing.T) {
	thisSpec := createOauthAppDefinition()
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

	if recorder.Code != 301 {
		t.Error("Request should have redirected, code should have been 301 but is: ", recorder.Code)
		t.Error(recorder.Body)
		t.Error(req.Body)
	}
}

func TestAPIClientAuthorizeAuthCode(t *testing.T) {
	thisSpec := createOauthAppDefinition()
	testMuxer := http.NewServeMux()
	getOAuthChain(thisSpec, testMuxer)

	uri := "/APIID/tyk/oauth/authorize-client/"
	method := "POST"

	param := make(url.Values)
	param.Set("response_type", "code")
	param.Set("redirect_uri", T_REDIRECT_URI)
	param.Set("client_id", T_CLIENT_ID)
	param.Set("key_rules", key_rules)
	req, err := http.NewRequest(method, uri, bytes.NewBufferString(param.Encode()))
	req.Header.Set("x-tyk-authorisation", "352d20ee67be67f6340b4c0605b044b7")
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
	testMuxer := http.NewServeMux()
	getOAuthChain(thisSpec, testMuxer)

	uri := "/APIID/tyk/oauth/authorize-client/"
	method := "POST"

	param := make(url.Values)
	param.Set("response_type", "token")
	param.Set("redirect_uri", T_REDIRECT_URI)
	param.Set("client_id", T_CLIENT_ID)
	param.Set("key_rules", key_rules)
	req, err := http.NewRequest(method, uri, bytes.NewBufferString(param.Encode()))
	req.Header.Set("x-tyk-authorisation", "352d20ee67be67f6340b4c0605b044b7")
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
	testMuxer := http.NewServeMux()
	getOAuthChain(thisSpec, testMuxer)

	uri := "/APIID/tyk/oauth/authorize-client/"
	method := "POST"

	param := make(url.Values)
	param.Set("response_type", "code")
	param.Set("redirect_uri", T_REDIRECT_URI)
	param.Set("client_id", T_CLIENT_ID)
	param.Set("key_rules", key_rules)
	req, _ := http.NewRequest(method, uri, bytes.NewBufferString(param.Encode()))
	req.Header.Set("x-tyk-authorisation", "352d20ee67be67f6340b4c0605b044b7")
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
	AccessToken string  `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func GetToken() tokenData {
	authData := GetAuthCode()

	thisSpec := createOauthAppDefinition()
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
	fmt.Println(string(body))
	err := json.Unmarshal(body, &thisResponse)
	if err != nil {
		fmt.Println(err)
	}

	return thisResponse
}

func TestClientAccessRequest(t *testing.T) {

	authData := GetAuthCode()

	thisSpec := createOauthAppDefinition()
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
