package main

import "net/http"

import (
	"encoding/base64"
	"github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
	"strings"
)

// BasicAuthKeyIsValid uses a username instead of
type BasicAuthKeyIsValid struct {
	TykMiddleware
}

// New creates a new HttpHandler for the alice middleware package
func (k BasicAuthKeyIsValid) New() func(http.Handler) http.Handler {
	aliceHandler := func(h http.Handler) http.Handler {
		thisHandler := func(w http.ResponseWriter, r *http.Request) {

			authHeaderValue := r.Header.Get("Authorization")
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

			bits := strings.Split(authHeaderValue, " ")
			if len(bits) != 2 {
				// Header malformed
				log.WithFields(logrus.Fields{
					"path":   r.URL.Path,
					"origin": r.RemoteAddr,
				}).Info("Attempted access with malformed header, header not in basic auth format.")

				handler := ErrorHandler{k.TykMiddleware}
				handler.HandleError(w, r, "Attempted access with malformed header, header not in basic auth format", 400)
				return
			}

			// Decode the username:password string
			authvaluesStr, err := base64.StdEncoding.DecodeString(bits[1])
			if err != nil {
				log.WithFields(logrus.Fields{
					"path":   r.URL.Path,
					"origin": r.RemoteAddr,
				}).Info("Base64 Decoding failed of basic auth data: ", err)

				handler := ErrorHandler{k.TykMiddleware}
				handler.HandleError(w, r, "Attempted access with malformed header, auth data not encoded correctly", 400)
				return
			}

			authValues := strings.Split(string(authvaluesStr), ":")
			if len(authValues) != 2 {
				// Header malformed
				log.WithFields(logrus.Fields{
					"path":   r.URL.Path,
					"origin": r.RemoteAddr,
				}).Info("Attempted access with malformed header, values not in basic auth format.")

				handler := ErrorHandler{k.TykMiddleware}
				handler.HandleError(w, r, "Attempted access with malformed header, values not in basic auth format", 400)
				return
			}

			// Check if API key valid
			keyName := k.TykMiddleware.Spec.OrgID + authValues[0]
			keyExists, thisSessionState := authManager.IsKeyAuthorised(keyName)
			if !keyExists {
				log.WithFields(logrus.Fields{
					"path":   r.URL.Path,
					"origin": r.RemoteAddr,
					"key":    keyName,
				}).Info("Attempted access with non-existent user.")

				handler := ErrorHandler{k.TykMiddleware}
				handler.HandleError(w, r, "User not authorised", 403)
				return
			}

			// Ensure that the username and password match up
			if thisSessionState.BasicAuthData.Password != authValues[1] {
				log.WithFields(logrus.Fields{
					"path":   r.URL.Path,
					"origin": r.RemoteAddr,
					"key":    keyName,
				}).Info("Attempted access with existing user but failed password check.")

				handler := ErrorHandler{k.TykMiddleware}
				handler.HandleError(w, r, "User not authorised", 403)
				return
			}

			// Set session state on context, we will need it later
			context.Set(r, SessionData, thisSessionState)
			context.Set(r, AuthHeaderValue, keyName)

			// Request is valid, carry on
			h.ServeHTTP(w, r)
		}

		return http.HandlerFunc(thisHandler)
	}

	return aliceHandler
}
