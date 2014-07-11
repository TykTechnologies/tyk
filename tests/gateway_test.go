package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"
	"github.com/justinas/alice"
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
	remote, _ := url.Parse("http://lonelycode.com/")
	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxyHandler := http.HandlerFunc(ProxyHandler(proxy, spec))
	tykMiddleware := TykMiddleware{spec, proxy}
	chain := alice.New(
		VersionCheck{tykMiddleware}.New(),
		KeyExists{tykMiddleware}.New(),
		KeyExpired{tykMiddleware}.New(),
		AccessRightsCheck{tykMiddleware}.New(),
		RateLimitAndQuotaCheck{tykMiddleware}.New()).Then(proxyHandler)

	return chain
}

func createNonVersionedDefinition() APISpec {
	var thisDef = APIDefinition{}
	var v1 = VersionInfo{}
	var thisSpec = APISpec{}
	var thisLoader = APIDefinitionLoader{}

	thisDef.Name = "Test API"
	thisDef.VersionDefinition.Key = "version"
	thisDef.VersionDefinition.Location = "header"
	thisDef.VersionData.NotVersioned = true

	v1.Name = "v1"
	thisDef.Auth.AuthHeaderName = "authorisation"
	v1.Expires = "2106-01-02 15:04"
	thisDef.Proxy.ListenPath = "/v1"
	thisDef.Proxy.TargetURL = "http://lonelycode.com"
	v1.Paths.Ignored = []string{"/v1/ignored/noregex", "/v1/ignored/with_id/{id}"}
	v1.Paths.BlackList = []string{"v1/disallowed/blacklist/literal", "v1/disallowed/blacklist/{id}"}

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


func TestThrottling(t *testing.T) {
	spec := createNonVersionedDefinition()
	thisSession := createThrottledSession()
	authManager.UpdateSession("1234", thisSession)
	uri := "/about-lonelycoder/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("authorisation", "1234")

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
	thisSession := createQuotaSession()
	authManager.UpdateSession("4321", thisSession)
	uri := "/about-lonelycoder/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("authorisation", "4321")

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
