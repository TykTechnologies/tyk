package main

import (
	"encoding/json"
	"github.com/justinas/alice"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"
)

func createThrottledSession() SessionState {
	var thisSession SessionState
	thisSession.Rate = 1.0
	thisSession.Allowance = thisSession.Rate
	thisSession.LastCheck = time.Now().Unix()
	thisSession.Per = 1.0
	thisSession.Expires = 0
	thisSession.QuotaRenewalRate = 300 // 5 minutes
	thisSession.QuotaRenews = time.Now().Unix()
	thisSession.QuotaRemaining = 10
	thisSession.QuotaMax = 10

	return thisSession
}

func createQuotaSession() SessionState {
	var thisSession SessionState
	thisSession.Rate = 8.0
	thisSession.Allowance = thisSession.Rate
	thisSession.LastCheck = time.Now().Unix()
	thisSession.Per = 1.0
	thisSession.Expires = 0
	thisSession.QuotaRenewalRate = 300 // 5 minutes
	thisSession.QuotaRenews = time.Now().Unix() + 20
	thisSession.QuotaRemaining = 1
	thisSession.QuotaMax = 1

	return thisSession
}

type TykErrorResponse struct {
	Error string
}

func getChain(spec APISpec) http.Handler {
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	spec.Init(&redisStore, &redisStore)
	remote, _ := url.Parse("http://lonelycode.com/")
	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxyHandler := http.HandlerFunc(ProxyHandler(proxy, spec))
	tykMiddleware := TykMiddleware{spec, proxy}
	chain := alice.New(
		CreateMiddleware(&IPWhiteListMiddleware{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&AuthKey{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&VersionCheck{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&KeyExpired{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&AccessRightsCheck{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&RateLimitAndQuotaCheck{tykMiddleware}, tykMiddleware)).Then(proxyHandler)

	return chain
}

var nonExpiringDefNoWhiteList string = `

	{
		"name": "Tyk Test API",
		"api_id": "1",
		"org_id": "default",
		"definition": {
			"location": "header",
			"key": "version"
		},
		"auth": {
			"auth_header_name": "authorization"
		},
		"version_data": {
			"not_versioned": true,
			"versions": {
				"v1": {
					"name": "v1",
					"expires": "3000-01-02 15:04",
					"paths": {
						"ignored": [],
						"black_list": [],
						"white_list": []
					}
				}
			}
		},
		"event_handlers": {
			"events": {
				"QuotaExceeded": [
					{
						"handler_name":"eh_log_handler",
						"handler_meta": {
							"prefix": "LOG-HANDLER-PREFIX"
						}
					},
					{
						"handler_name":"eh_log_handler",
						"handler_meta": {
							"prefix": "ANOTHER-LOG-HANDLER-PREFIX"
						}
					}
				]
			}
		},
		"proxy": {
			"listen_path": "/v1",
			"target_url": "http://lonelycode.com",
			"strip_listen_path": false
		}
	}

`

func createNonVersionedDefinition() APISpec {

	return createDefinitionFromString(nonExpiringDefNoWhiteList)

}

func TestThrottling(t *testing.T) {
	spec := createNonVersionedDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	spec.Init(&redisStore, &redisStore)
	thisSession := createThrottledSession()
	spec.SessionManager.UpdateSession("1234", thisSession, 60)
	uri := "/about-lonelycoder/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("authorization", "1234")

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code: \n", recorder.Code)
	}

	secondRecorder := httptest.NewRecorder()
	chain.ServeHTTP(secondRecorder, req)

	thirdRecorder := httptest.NewRecorder()
	chain.ServeHTTP(thirdRecorder, req)

	if thirdRecorder.Code == 200 {
		t.Error("Third request failed, should not be 200!: \n", thirdRecorder.Code)
	}
	if thirdRecorder.Code != 403 {
		t.Error("Third request returned invalid code, should 403, got: \n", thirdRecorder.Code)
	}

	newAPIError := TykErrorResponse{}
	json.Unmarshal([]byte(thirdRecorder.Body.String()), &newAPIError)

	if newAPIError.Error != "Rate limit exceeded" {
		t.Error("Third request returned invalid message, got: \n", thirdRecorder.Code)
	}
}

func TestQuota(t *testing.T) {
	spec := createNonVersionedDefinition()
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	spec.Init(&redisStore, &redisStore)
	thisSession := createQuotaSession()
	spec.SessionManager.UpdateSession("4321", thisSession, 60)
	uri := "/about-lonelycoder/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("authorization", "4321")

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code: \n", recorder.Code)
	}

	secondRecorder := httptest.NewRecorder()
	chain.ServeHTTP(secondRecorder, req)
	thirdRecorder := httptest.NewRecorder()
	chain.ServeHTTP(thirdRecorder, req)

	if thirdRecorder.Code == 200 {
		t.Error("Third request failed, should not be 200!: \n", thirdRecorder.Code)
	}
	if thirdRecorder.Code != 403 {
		t.Error("Third request returned invalid code, should 403, got: \n", thirdRecorder.Code)
	}

	newAPIError := TykErrorResponse{}
	json.Unmarshal([]byte(thirdRecorder.Body.String()), &newAPIError)

	if newAPIError.Error != "Quota exceeded" {
		t.Error("Third request returned invalid message, got: \n", newAPIError.Error)
	}
}
