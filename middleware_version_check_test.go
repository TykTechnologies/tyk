package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVersionMwExpiresHeader(t *testing.T) {
	spec := createSpecTest(t, nonExpiringDef)
	loadApps([]*APISpec{spec}, discardMuxer)

	session := createNonThrottledSession()
	spec.SessionManager.UpdateSession("1234xyz", session, 60)

	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/v1/ignored/noregex", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "127.0.0.1:80"
	req.Header.Add("authorization", "1234xyz")
	req.Header.Add("version", "v1")

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Invalid response code, should be 200: ", recorder.Code)
	}

	want := "Thu, 02 Jan 3000 15:04:00 UTC"
	if got := recorder.Result().Header.Get("x-tyk-api-expires"); got != want {
		t.Errorf("expires header want %q, got %q", want, got)
	}
}
