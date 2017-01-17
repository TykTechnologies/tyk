package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/justinas/alice"
)

var basicAuthDef = `

	{
		"name": "Tyk Test API",
		"api_id": "1",
		"org_id": "default",
		"definition": {
			"location": "header",
			"key": "version"
		},
		"use_basic_auth": true,
		"auth": {
			"auth_header_name": "authorization"
		},
		"version_data": {
			"not_versioned": true,
			"versions": {
				"Default": {
					"name": "Default",
					"use_extended_paths": true,
					"expires": "3000-01-02 15:04",
					"paths": {
						"ignored": [],
						"white_list": [],
						"black_list": []
					}
				}
			}
		},
		"proxy": {
			"listen_path": "/v1",
			"target_url": "http://example.com/",
			"strip_listen_path": true
		}
	}

`

func createBasicAuthSession() SessionState {
	var thisSession SessionState
	thisSession.Rate = 8.0
	thisSession.Allowance = thisSession.Rate
	thisSession.LastCheck = time.Now().Unix()
	thisSession.Per = 1.0
	thisSession.Expires = 0
	thisSession.QuotaRenewalRate = 300 // 5 minutes
	thisSession.QuotaRenews = time.Now().Unix() + 20
	thisSession.QuotaRemaining = 1
	thisSession.QuotaMax = -1
	thisSession.BasicAuthData.Password = "TEST"

	return thisSession
}

func getBasicAuthChain(spec *APISpec) http.Handler {
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	remote, _ := url.Parse("http://example.com/")
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	proxyHandler := http.HandlerFunc(ProxyHandler(proxy, spec))
	tykMiddleware := &TykMiddleware{spec, proxy}
	chain := alice.New(
		CreateMiddleware(&IPWhiteListMiddleware{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&BasicAuthKeyIsValid{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&VersionCheck{TykMiddleware: tykMiddleware}, tykMiddleware),
		CreateMiddleware(&KeyExpired{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&AccessRightsCheck{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&RateLimitAndQuotaCheck{tykMiddleware}, tykMiddleware)).Then(proxyHandler)

	return chain
}

func TestBasicAuthSession(t *testing.T) {
	spec := createDefinitionFromString(basicAuthDef)
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createBasicAuthSession()
	username := "4321"
	password := "TEST"
	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default4321", thisSession, 60)

	to_encode := strings.Join([]string{username, password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encodedPass))

	if err != nil {
		t.Fatal(err)
	}

	chain := getBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
	}
}

func TestBasicAuthBadFormatting(t *testing.T) {
	spec := createDefinitionFromString(basicAuthDef)
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createBasicAuthSession()
	username := "4321"
	password := "TEST"
	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default4321", thisSession, 60)

	to_encode := strings.Join([]string{username, password}, "-")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encodedPass))

	if err != nil {
		t.Fatal(err)
	}

	chain := getBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Request should have failed and returned non-200 code!: \n", recorder.Code)
	}

	if recorder.Code != 400 {
		t.Error("Request didn't return 400 code!: \n", recorder.Code)
	}
}

func TestBasicAuthBadData(t *testing.T) {
	spec := createDefinitionFromString(basicAuthDef)
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createBasicAuthSession()
	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default4321", thisSession, 60)

	to_encode := "ldhflsdflksjfdlksjflksdjlskdjflkjsfd:::jhdsgfkjahsgdkhasdgjhgasdjhads:::aksdakjsdh:adskasdkjhasdkjhad-asdads"
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encodedPass))

	if err != nil {
		t.Fatal(err)
	}

	chain := getBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Request should have failed and returned non-200 code!: \n", recorder.Code)
	}

	if recorder.Code != 400 {
		t.Error("Request didn't return 400 code!: \n", recorder.Code)
	}
}

func TestBasicAuthBadOverFormatting(t *testing.T) {
	spec := createDefinitionFromString(basicAuthDef)
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createBasicAuthSession()
	username := "4321"
	password := "TEST"
	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default4321", thisSession, 60)

	to_encode := strings.Join([]string{username, password, "banana"}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encodedPass))

	if err != nil {
		t.Fatal(err)
	}

	chain := getBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Request should have failed and returned non-200 code!: \n", recorder.Code)
	}

	if recorder.Code != 400 {
		t.Error("Request didn't return 400 code!: \n", recorder.Code)
	}
}

func TestBasicAuthWrongUser(t *testing.T) {
	spec := createDefinitionFromString(basicAuthDef)
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createBasicAuthSession()
	password := "TEST"
	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default4321", thisSession, 60)

	to_encode := strings.Join([]string{"1234", password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encodedPass))

	if err != nil {
		t.Fatal(err)
	}

	chain := getBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Request should have failed and returned non-200 code!: \n", recorder.Code)
	}

	if recorder.Code != 401 {
		t.Error("Request should have returned 401 code!: \n", recorder.Code)
	}

	if recorder.Header().Get("WWW-Authenticate") == "" {
		t.Error("Request should have returned WWW-Authenticate header!: \n")
	}
}

func TestBasicMissingHeader(t *testing.T) {
	spec := createDefinitionFromString(basicAuthDef)
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createBasicAuthSession()

	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default4321", thisSession, 60)

	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)

	if err != nil {
		t.Fatal(err)
	}

	chain := getBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Request should have failed and returned non-200 code!: \n", recorder.Code)
	}

	if recorder.Code != 401 {
		t.Error("Request should have returned 401 code!: \n", recorder.Code)
	}
}

func TestBasicAuthWrongPassword(t *testing.T) {
	spec := createDefinitionFromString(basicAuthDef)
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createBasicAuthSession()
	username := "4321"

	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default4321", thisSession, 60)

	to_encode := strings.Join([]string{username, "WRONGPASSTEST"}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encodedPass))

	if err != nil {
		t.Fatal(err)
	}

	chain := getBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Request should have failed and returned non-200 code!: \n", recorder.Code)
	}

	if recorder.Code != 401 {
		t.Error("Request should have returned 401 code!: \n", recorder.Code)
	}

	if recorder.Header().Get("WWW-Authenticate") == "" {
		t.Error("Request should have returned WWW-Authenticate header!: \n")
	}
}
