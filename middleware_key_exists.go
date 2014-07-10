package main

import "net/http"

import (
	"github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
)

// KeyExists will check if the key being used to access the API is in the request data,
// and then if the key is in the storage engine
type KeyExists struct {
	TykMiddleware
}

// New creates a new HttpHandler for the alice middleware package
func (k KeyExists) New() func(http.Handler) http.Handler {
	aliceHandler := func(h http.Handler) http.Handler {
		thisHandler := func(w http.ResponseWriter, r *http.Request) {

			authHeaderValue := r.Header.Get(k.Spec.APIDefinition.Auth.AuthHeaderName)
			if authHeaderValue == "" {
				// No header value, fail
				log.WithFields(logrus.Fields{
					"path":   r.URL.Path,
					"origin": r.RemoteAddr,
				}).Info("Attempted access with malformed header, no auth header found.")

				handler := ErrorHandler{k.TykMiddleware}
				handler.HandleError(w, r, "Authorisation field missing", 400)
				return
			}

			// Check if API key valid
			keyExists, thisSessionState := authManager.IsKeyAuthorised(authHeaderValue)
			if !keyExists {
				log.WithFields(logrus.Fields{
					"path":   r.URL.Path,
					"origin": r.RemoteAddr,
					"key":    authHeaderValue,
				}).Info("Attempted access with non-existent key.")

				handler := ErrorHandler{k.TykMiddleware}
				handler.HandleError(w, r, "Key not authorised", 403)
				return
			}

			// Set session state on context, we will need it later
			context.Set(r, SessionData, thisSessionState)
			context.Set(r, AuthHeaderValue, authHeaderValue)

			// Request is valid, carry on
			h.ServeHTTP(w, r)
		}

		return http.HandlerFunc(thisHandler)
	}

	return aliceHandler
}
