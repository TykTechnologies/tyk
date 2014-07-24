package main

import (
	"fmt"
	"github.com/gorilla/context"
	"net/http"
	"runtime/pprof"
	"strings"
	"time"
)

// APIError is generic error object returned if there is something wrong with the request
type APIError struct {
	Message string
}

// ErrorHandler is invoked whenever there is an issue with a proxied request, most middleware will invoke
// the ErrorHandler if something is wrong with the request and halt the request processing through the chain
type ErrorHandler struct {
	TykMiddleware
}

// HandleError is the actual error handler and will store the error details in analytics if analytics processing is enabled.
func (e ErrorHandler) HandleError(w http.ResponseWriter, r *http.Request, err string, errCode int) {
	if config.EnableAnalytics {
		t := time.Now()

		// Track the key ID if it exists
		authHeaderValue := context.Get(r, AuthHeaderValue)
		keyName := ""
		if authHeaderValue != nil {
			keyName = authHeaderValue.(string)
		}

		version := e.Spec.getVersionFromRequest(r)
		if version == "" {
			version = "Non Versioned"
		}

		if e.TykMiddleware.Spec.APIDefinition.Proxy.StripListenPath {
			r.URL.Path = strings.Replace(r.URL.Path, e.TykMiddleware.Spec.Proxy.ListenPath, "", 1)
		}

		OauthClientID := ""
		thisSessionState := context.Get(r, SessionData)

		if thisSessionState != nil {
			OauthClientID = thisSessionState.(SessionState).OauthClientID
		}

		thisRecord := AnalyticsRecord{
			r.Method,
			r.URL.Path,
			r.ContentLength,
			r.Header.Get("User-Agent"),
			t.Day(),
			t.Month(),
			t.Year(),
			t.Hour(),
			errCode,
			keyName,
			t,
			version,
			e.Spec.APIDefinition.Name,
			e.Spec.APIDefinition.APIID,
			e.Spec.APIDefinition.OrgID,
			OauthClientID}
		go analytics.RecordHit(thisRecord)
	}

	w.WriteHeader(errCode)
	w.Header().Add("Content-Type", "application/json")
	w.Header().Add("X-Generator", "tyk.io")
	thisError := APIError{fmt.Sprintf("%s", err)}
	templates.ExecuteTemplate(w, "error.json", &thisError)
	if doMemoryProfile {
		pprof.WriteHeapProfile(profileFile)
	}

	// Clean up
	context.Clear(r)
}
