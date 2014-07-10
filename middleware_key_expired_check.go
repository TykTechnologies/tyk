package main

import "net/http"

import (
	"github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
)

// KeyExpired middleware will check if the requesting key is expired or not. It makes use of the authManager to do so.
type KeyExpired struct {
	TykMiddleware
}

// New creates a new HttpHandler for the alice middleware package
func (k KeyExpired) New() func(http.Handler) http.Handler {
	aliceHandler := func(h http.Handler) http.Handler {
		thisHandler := func(w http.ResponseWriter, r *http.Request) {

			thisSessionState := context.Get(r, SessionData).(SessionState)
			authHeaderValue := context.Get(r, AuthHeaderValue).(string)
			keyExpired := authManager.IsKeyExpired(&thisSessionState)

			if keyExpired {
				log.WithFields(logrus.Fields{
					"path":   r.URL.Path,
					"origin": r.RemoteAddr,
					"key":    authHeaderValue,
				}).Info("Attempted access from expired key.")
				handler := ErrorHandler{k.TykMiddleware}
				handler.HandleError(w, r, "Key has expired, please renew", 403)
				return
			}

			// Request is valid, carry on
			h.ServeHTTP(w, r)
		}

		return http.HandlerFunc(thisHandler)
	}

	return aliceHandler
}
