package main

import "net/http"

import (
	"errors"
	"github.com/TykTechnologies/logrus"
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

func (a *KeyExpired) IsEnabledForSpec() bool {
	return true
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *KeyExpired) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	sess, ok := context.GetOk(r, SessionData)

	if !ok {
		return errors.New("Session state is missing or unset! Please make sure that auth headers are properly applied."), 403
	}

	thisSessionState := sess.(SessionState)

	if thisSessionState.IsInactive {
		authHeaderValue := context.Get(r, AuthHeaderValue).(string)
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
			"key":    authHeaderValue,
		}).Info("Attempted access from inactive key.")

		// Fire a key expired event
		go k.TykMiddleware.FireEvent(EVENT_KeyExpired,
			EVENT_KeyExpiredMeta{
				EventMetaDefault: EventMetaDefault{Message: "Attempted access from inactive key.", OriginatingRequest: EncodeRequestToEvent(r)},
				Path:             r.URL.Path,
				Origin:           GetIPFromRequest(r),
				Key:              authHeaderValue,
			})

		// Report in health check
		ReportHealthCheckValue(k.Spec.Health, KeyFailure, "-1")

		return errors.New("Key is inactive, please renew"), 403
	}

	keyExpired := k.Spec.AuthManager.IsKeyExpired(&thisSessionState)

	if keyExpired {
		authHeaderValue := context.Get(r, AuthHeaderValue).(string)
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
			"key":    authHeaderValue,
		}).Info("Attempted access from expired key.")

		// Fire a key expired event
		go k.TykMiddleware.FireEvent(EVENT_KeyExpired,
			EVENT_KeyExpiredMeta{
				EventMetaDefault: EventMetaDefault{Message: "Attempted access from expired key."},
				Path:             r.URL.Path,
				Origin:           GetIPFromRequest(r),
				Key:              authHeaderValue,
			})

		// Report in health check
		ReportHealthCheckValue(k.Spec.Health, KeyFailure, "-1")

		return errors.New("Key has expired, please renew"), 403
	}

	return nil, 200
}
