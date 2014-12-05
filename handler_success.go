package main

import (
	"github.com/gorilla/context"
	"net/http"
	"net/http/httputil"
	"runtime/pprof"
	"strings"
	"time"
)

// ContextKey is a key type to avoid collisions
type ContextKey int

// Enums for keys to be stored in a session context - this is how gorilla expects
// these to be implemented and is lifted pretty much from docs
const (
	SessionData     = 0
	AuthHeaderValue = 1
)

// TykMiddleware wraps up the ApiSpec and Proxy objects to be included in a
// middleware handler, this can probably be handled better.
type TykMiddleware struct {
	Spec  APISpec
	Proxy *httputil.ReverseProxy
}

// CheckSessionAndIdentityForValidKey will check first the Session store for a valid key, if not found, it will try
// the Auth Handler, if not found it will fail
func (t TykMiddleware) CheckSessionAndIdentityForValidKey(key string) (SessionState, bool) {
	// Try and get the session from the session store
	var thisSession SessionState
	var found bool

	thisSession, found = t.Spec.SessionManager.GetSessionDetail(key)
	if found {
		// If exists, assume it has been authorized and pass on
		return thisSession, true
	}

	// 2. If not there, get it from the AuthorizationHandler

	thisSession, found = t.Spec.AuthManager.IsKeyAuthorised(key)
	if found {
		// If not in Session, and got it from AuthHandler, create a session with a new TTL
		log.Info("Recreating session for key: ", key)
		t.Spec.SessionManager.UpdateSession(key, thisSession, t.Spec.APIDefinition.SessionLifetime)
	}

	return thisSession, found
}

// SuccessHandler represents the final ServeHTTP() request for a proxied API request
type SuccessHandler struct {
	TykMiddleware
}

// ServeHTTP will store the request details in the analytics store if necessary and proxy the request to it's
// final destination, this is invoked by the ProxyHandler or right at the start of a request chain if the URL
// Spec states the path is Ignored
func (s SuccessHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {



	// Make sure we get the correct target URL
	if s.Spec.APIDefinition.Proxy.StripListenPath {
		r.URL.Path = strings.Replace(r.URL.Path, s.Spec.Proxy.ListenPath, "", 1)
	}



	t1 := time.Now()
	s.Proxy.ServeHTTP(w, r)
	t2 := time.Now()

	millisec := float64(t2.UnixNano() - t1.UnixNano()) * 0.000001
	log.Info("Upstream request took (ms): ", millisec)

	if config.StoreAnalytics(r) {
		t := time.Now()

		// Track the key ID if it exists
		authHeaderValue := context.Get(r, AuthHeaderValue)
		keyName := ""
		if authHeaderValue != nil {
			keyName = authHeaderValue.(string)
		}

		// Track version data
		version := s.Spec.getVersionFromRequest(r)
		if version == "" {
			version = "Non Versioned"
		}

		// If OAuth, we need to grab it from the session, which may or may not exist
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
			200,
			keyName,
			t,
			version,
			s.Spec.APIDefinition.Name,
			s.Spec.APIDefinition.APIID,
			s.Spec.APIDefinition.OrgID,
			OauthClientID,
			int64(millisec)}

		go analytics.RecordHit(thisRecord)
	}

	if doMemoryProfile {
		pprof.WriteHeapProfile(profileFile)
	}

	context.Clear(r)
}
