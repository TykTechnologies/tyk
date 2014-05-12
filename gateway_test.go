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

func TestThrottling(t *testing.T) {
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
	handler(thisProxy)(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code: \n", recorder.Code)
	}

	second_recorder := httptest.NewRecorder()
	handler(thisProxy)(second_recorder, req)
	third_recorder := httptest.NewRecorder()
	handler(thisProxy)(third_recorder, req)

	if third_recorder.Code == 200 {
		t.Error("Third request failed, should not be 200!: \n", third_recorder.Body.String())
	}
	if third_recorder.Code != 429 {
		t.Error("Third request returned invalid code, should 429, got: \n", third_recorder.Code)
	}

	newApiError := TykErrorResponse{}
	json.Unmarshal([]byte(third_recorder.Body.String()), &newApiError)

	if newApiError.Error != "Rate limit exceeded" {
		t.Error("Third request returned invalid message, got: \n", third_recorder.Body.String())
	}
}

func TestQuota(t *testing.T) {
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
	handler(thisProxy)(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code: \n", recorder.Code)
	}

	second_recorder := httptest.NewRecorder()
	handler(thisProxy)(second_recorder, req)
	third_recorder := httptest.NewRecorder()
	handler(thisProxy)(third_recorder, req)

	if third_recorder.Code == 200 {
		t.Error("Third request failed, should not be 200!: \n", third_recorder.Code)
	}
	if third_recorder.Code != 429 {
		t.Error("Third request returned invalid code, should 429, got: \n", third_recorder.Code)
	}

	newApiError := TykErrorResponse{}
	json.Unmarshal([]byte(third_recorder.Body.String()), &newApiError)

	if newApiError.Error != "Quota exceeded" {
		t.Error("Third request returned invalid message, got: \n", newApiError.Error)
	}
}
