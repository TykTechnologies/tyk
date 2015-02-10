package main

import "net/http"

import (
	"errors"
	"github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
)

// KeyExists will check if the key being used to access the API is in the request data,
// and then if the key is in the storage engine
type AuthKey struct {
	TykMiddleware
}

func (k AuthKey) New() {}

// GetConfig retrieves the configuration from the API config
func (k *AuthKey) GetConfig() (interface{}, error) {
	return k.TykMiddleware.Spec.APIDefinition.Auth, nil
}

func (k *AuthKey) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	thisConfig := k.TykMiddleware.Spec.APIDefinition.Auth

	authHeaderValue := r.Header.Get(thisConfig.AuthHeaderName)
	if authHeaderValue == "" {
		// No header value, fail
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": r.RemoteAddr,
		}).Info("Attempted access with malformed header, no auth header found.")

		return errors.New("Authorization field missing"), 400
	}

	// Check if API key valid
	thisSessionState, keyExists := k.TykMiddleware.CheckSessionAndIdentityForValidKey(authHeaderValue)
	if !keyExists {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": r.RemoteAddr,
			"key":    authHeaderValue,
		}).Info("Attempted access with non-existent key.")

		// Fire Authfailed Event
		AuthFailed(k.TykMiddleware, r, authHeaderValue)

		// Report in health check
		ReportHealthCheckValue(k.Spec.Health, KeyFailure, "1")

		return errors.New("Key not authorised"), 403
	}

	// Set session state on context, we will need it later
	context.Set(r, SessionData, thisSessionState)
	context.Set(r, AuthHeaderValue, authHeaderValue)

	return nil, 200
}

func AuthFailed(m TykMiddleware, r *http.Request, authHeaderValue string) {
	go m.FireEvent(EVENT_AuthFailure,
		EVENT_AuthFailureMeta{
            EventMetaDefault: EventMetaDefault{Message: "Auth Failure", OriginatingRequest: EncodeRequestToEvent(r)},
			Path:             r.URL.Path,
			Origin:           r.RemoteAddr,
			Key:              authHeaderValue,
		})
}
