package main

import (
	"errors"
	"net/http"

	"github.com/Sirupsen/logrus"
)

// KeyExpired middleware will check if the requesting key is expired or not. It makes use of the authManager to do so.
type KeyExpired struct {
	BaseMiddleware
}

func (k *KeyExpired) Name() string {
	return "KeyExpired"
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *KeyExpired) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	session := ctxGetSession(r)
	if session == nil {
		return errors.New("Session state is missing or unset! Please make sure that auth headers are properly applied"), 400
	}

	token := ctxGetAuthToken(r)
	if session.IsInactive {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": requestIP(r),
			"key":    token,
		}).Info("Attempted access from inactive key.")

		// Fire a key expired event
		k.FireEvent(EventKeyExpired, EventKeyExpiredMeta{
			EventMetaDefault: EventMetaDefault{Message: "Attempted access from inactive key.", OriginatingRequest: EncodeRequestToEvent(r)},
			Path:             r.URL.Path,
			Origin:           requestIP(r),
			Key:              token,
		})

		// Report in health check
		reportHealthValue(k.Spec, KeyFailure, "-1")

		return errors.New("Key is inactive, please renew"), 403
	}

	if !k.Spec.AuthManager.IsKeyExpired(session) {
		return nil, 200
	}
	log.WithFields(logrus.Fields{
		"path":   r.URL.Path,
		"origin": requestIP(r),
		"key":    token,
	}).Info("Attempted access from expired key.")

	// Report in health check
	reportHealthValue(k.Spec, KeyFailure, "-1")

	return errors.New("Key has expired, please renew"), 401
}
