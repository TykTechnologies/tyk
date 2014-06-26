package main

import (
	"encoding/json"
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

func createNonVersionedDefinition() ApiSpec {
	var thisDef = ApiDefinition{}
	var v1 = VersionInfo{}
	var thisSpec = ApiSpec{}
	var thisLoader = ApiDefinitionLoader{}

	thisDef.Name = "Test API"
	thisDef.VersionDefinition.Key = "version"
	thisDef.VersionDefinition.Location = "header"
	thisDef.VersionData.NotVersioned = true

	v1.Name = "v1"
	thisDef.Auth.AuthHeaderName = "authorisation"
	v1.Expires = "2106-01-02 15:04"
	thisDef.Proxy.ListenPath = "/v1"
	thisDef.Proxy.TargetUrl = "http://lonelycode.com"
	v1.Paths.Ignored = []string{"/v1/ignored/noregex", "/v1/ignored/with_id/{id}"}
	v1.Paths.BlackList = []string{"v1/disallowed/blacklist/literal", "v1/disallowed/blacklist/{id}"}

	thisDef.VersionData.Versions = make(map[string]VersionInfo)
	thisDef.VersionData.Versions[v1.Name] = v1

	thisSpec.ApiDefinition = thisDef

	thisSpec.RxPaths = make(map[string][]UrlSpec)
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

	remote, _ := url.Parse("http://lonelycode.com/")
	thisProxy := httputil.NewSingleHostReverseProxy(remote)
	handler(thisProxy, spec)(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code: \n", recorder.Code)
	}

	second_recorder := httptest.NewRecorder()
	handler(thisProxy, spec)(second_recorder, req)
	third_recorder := httptest.NewRecorder()
	handler(thisProxy, spec)(third_recorder, req)

	if third_recorder.Code == 200 {
		t.Error("Third request failed, should not be 200!: \n", third_recorder.Body.String())
	}
	if third_recorder.Code != 409 {
		t.Error("Third request returned invalid code, should 409, got: \n", third_recorder.Code)
	}

	newApiError := TykErrorResponse{}
	json.Unmarshal([]byte(third_recorder.Body.String()), &newApiError)

	if newApiError.Error != "Rate limit exceeded" {
		t.Error("Third request returned invalid message, got: \n", third_recorder.Body.String())
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

	remote, _ := url.Parse("http://lonelycode.com/")
	thisProxy := httputil.NewSingleHostReverseProxy(remote)
	handler(thisProxy, spec)(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code: \n", recorder.Code)
	}

	second_recorder := httptest.NewRecorder()
	handler(thisProxy, spec)(second_recorder, req)
	third_recorder := httptest.NewRecorder()
	handler(thisProxy, spec)(third_recorder, req)

	if third_recorder.Code == 200 {
		t.Error("Third request failed, should not be 200!: \n", third_recorder.Code)
	}
	if third_recorder.Code != 409 {
		t.Error("Third request returned invalid code, should 409, got: \n", third_recorder.Code)
	}

	newApiError := TykErrorResponse{}
	json.Unmarshal([]byte(third_recorder.Body.String()), &newApiError)

	if newApiError.Error != "Quota exceeded" {
		t.Error("Third request returned invalid message, got: \n", newApiError.Error)
	}
}
