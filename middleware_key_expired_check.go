package main

import "net/http"

import (
	"errors"
	"github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
)

// KeyExpired middleware will check if the requesting key is expired or not. It makes use of the authManager to do so.
type KeyExpired struct {
	*TykMiddleware
}

// New lets you do any initialisations for the object can be done here
func (k *KeyExpired) New() {}

// GetConfig retrieves the configuration from the API config - Not used for this middleware
func (k *KeyExpired) GetConfig() (interface{}, error) {
	return nil, nil
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *KeyExpired) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	thisSessionState := context.Get(r, SessionData).(SessionState)
	authHeaderValue := context.Get(r, AuthHeaderValue).(string)

	if thisSessionState.IsInactive {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": r.RemoteAddr,
			"key":    authHeaderValue,
		}).Info("Attempted access from inactive key.")

		// Fire a key expired event
		authHeaderValue := context.Get(r, AuthHeaderValue)
		go k.TykMiddleware.FireEvent(EVENT_KeyExpired,
			EVENT_KeyExpiredMeta{
				EventMetaDefault: EventMetaDefault{Message: "Attempted access from inactive key.", OriginatingRequest: EncodeRequestToEvent(r)},
				Path:             r.URL.Path,
				Origin:           r.RemoteAddr,
				Key:              authHeaderValue.(string),
			})

		// Report in health check
		ReportHealthCheckValue(k.Spec.Health, KeyFailure, "1")

		return errors.New("Key is inactive, please renew"), 403
	}

	keyExpired := k.Spec.AuthManager.IsKeyExpired(&thisSessionState)

	if keyExpired {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": r.RemoteAddr,
			"key":    authHeaderValue,
		}).Info("Attempted access from expired key.")

		// Fire a key expired event
		authHeaderValue := context.Get(r, AuthHeaderValue)
		go k.TykMiddleware.FireEvent(EVENT_KeyExpired,
			EVENT_KeyExpiredMeta{
				EventMetaDefault: EventMetaDefault{Message: "Attempted access from expired key."},
				Path:             r.URL.Path,
				Origin:           r.RemoteAddr,
				Key:              authHeaderValue.(string),
			})

		// Report in health check
		ReportHealthCheckValue(k.Spec.Health, KeyFailure, "1")

		return errors.New("Key has expired, please renew"), 403
	}

	return nil, 200
}
