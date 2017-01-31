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

var multiAuthDev = `

	{
		"name": "Tyk Test API",
		"api_id": "55",
		"org_id": "default",
		"definition": {
			"location": "header",
			"key": "version"
		},
		"use_basic_auth": true,
		"use_standard_auth": true,
		"base_identity_provided_by": "auth_token",
		"auth": {
			"auth_header_name": "x-standard-auth"
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

func createMultiAuthKeyAuthSession() SessionState {
	var thisSession SessionState
	// essentially non-throttled
	thisSession.Rate = 100.0
	thisSession.Allowance = thisSession.Rate
	thisSession.LastCheck = time.Now().Unix()
	thisSession.Per = 1.0
	thisSession.Expires = 0
	thisSession.QuotaRenewalRate = 300 // 5 minutes
	thisSession.QuotaRenews = time.Now().Unix()
	thisSession.QuotaRemaining = 900
	thisSession.QuotaMax = 10
	thisSession.AccessRights = map[string]AccessDefinition{"55": {APIName: "Tyk Multi Key Test", APIID: "55", Versions: []string{"default"}}}

	return thisSession
}

func createMultiBasicAuthSession() SessionState {
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
	thisSession.AccessRights = map[string]AccessDefinition{"55": {APIName: "Tyk Multi Key Test", APIID: "55", Versions: []string{"default"}}}

	return thisSession
}

func getMultiAuthStandardAndBasicAuthChain(spec *APISpec) http.Handler {
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	remote, _ := url.Parse("http://example.com/")
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	proxyHandler := http.HandlerFunc(ProxyHandler(proxy, spec))
	tykMiddleware := &TykMiddleware{spec, proxy}
	chain := alice.New(
		CreateMiddleware(&IPWhiteListMiddleware{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&BasicAuthKeyIsValid{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&AuthKey{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&VersionCheck{TykMiddleware: tykMiddleware}, tykMiddleware),
		CreateMiddleware(&KeyExpired{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&AccessRightsCheck{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&RateLimitAndQuotaCheck{tykMiddleware}, tykMiddleware)).Then(proxyHandler)

	return chain
}

func TestMultiSession_BA_Standard_OK(t *testing.T) {
	spec := createDefinitionFromString(multiAuthDev)
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)

	// Create BA
	baSession := createMultiBasicAuthSession()
	username := "0987876"
	password := "TEST"
	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default0987876", baSession, 60)

	// Create key
	thisSession := createMultiAuthKeyAuthSession()
	customToken := "84573485734587384888723487243"
	// AuthKey sessions are stored by {token}
	spec.SessionManager.UpdateSession(customToken, thisSession, 60)

	to_encode := strings.Join([]string{username, password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encodedPass))
	req.Header.Add("x-standard-auth", fmt.Sprintf("Bearer %s", customToken))

	if err != nil {
		t.Fatal(err)
	}

	chain := getMultiAuthStandardAndBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
	}
}

func TestMultiSession_BA_Standard_Identity(t *testing.T) {
	spec := createDefinitionFromString(multiAuthDev)
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)

	// Create BA
	baSession := createMultiBasicAuthSession()
	username := "0987876"
	password := "TEST"
	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default0987876", baSession, 60)

	// Create key
	thisSession := createMultiAuthKeyAuthSession()
	customToken := "84573485734587384888723487243"
	// AuthKey sessions are stored by {token}
	spec.SessionManager.UpdateSession(customToken, thisSession, 60)

	to_encode := strings.Join([]string{username, password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encodedPass))
	req.Header.Add("x-standard-auth", fmt.Sprintf("Bearer %s", customToken))

	if err != nil {
		t.Fatal(err)
	}

	chain := getMultiAuthStandardAndBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
	}

	if recorder.Header().Get("X-Ratelimit-Remaining") == "-1" {
		t.Error("Expected quota limit but found -1, wrong base identity became context")
		t.Error(recorder.Header().Get("X-Ratelimit-Remaining"))
	}
}

func TestMultiSession_BA_Standard_FAILBA(t *testing.T) {
	spec := createDefinitionFromString(multiAuthDev)
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)

	// Create BA
	baSession := createMultiBasicAuthSession()
	username := "0987876"
	password := "WRONG"
	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default0987876", baSession, 60)

	// Create key
	thisSession := createMultiAuthKeyAuthSession()
	customToken := "84573485734587384888723487243"
	// AuthKey sessions are stored by {token}
	spec.SessionManager.UpdateSession(customToken, thisSession, 60)

	to_encode := strings.Join([]string{username, password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encodedPass))
	req.Header.Add("x-standard-auth", fmt.Sprintf("Bearer %s", customToken))

	if err != nil {
		t.Fatal(err)
	}

	chain := getMultiAuthStandardAndBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 401 {
		t.Error("Wrong response code received, expected 401: \n", recorder.Code)
	}
}

func TestMultiSession_BA_Standard_FAILAuth(t *testing.T) {
	spec := createDefinitionFromString(multiAuthDev)
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)

	// Create BA
	baSession := createMultiBasicAuthSession()
	username := "0987876"
	password := "TEST"
	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default0987876", baSession, 60)

	// Create key
	thisSession := createMultiAuthKeyAuthSession()
	customToken := "84573485734587384888723487243"
	// AuthKey sessions are stored by {token}
	spec.SessionManager.UpdateSession(customToken, thisSession, 60)

	to_encode := strings.Join([]string{username, password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encodedPass))
	req.Header.Add("x-standard-auth", fmt.Sprintf("Bearer %s", "WRONGTOKEN"))

	if err != nil {
		t.Fatal(err)
	}

	chain := getMultiAuthStandardAndBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 403 {
		t.Error("Wrong response code received, expected 403: \n", recorder.Code)
	}
}
