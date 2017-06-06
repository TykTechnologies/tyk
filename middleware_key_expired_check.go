package main

import (
	"errors"
	"net/http"

	"github.com/Sirupsen/logrus"
)

// KeyExpired middleware will check if the requesting key is expired or not. It makes use of the authManager to do so.
type KeyExpired struct {
	*TykMiddleware
}

func (k *KeyExpired) GetName() string {
	return "KeyExpired"
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *KeyExpired) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	session := ctxGetSession(r)
	if session == nil {
		return errors.New("Session state is missing or unset! Please make sure that auth headers are properly applied"), 400
	}

	token := ctxGetAuthToken(r)
	if session.IsInactive {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
			"key":    token,
		}).Info("Attempted access from inactive key.")

		// Fire a key expired event
		k.FireEvent(EventKeyExpired, EventKeyExpiredMeta{
			EventMetaDefault: EventMetaDefault{Message: "Attempted access from inactive key.", OriginatingRequest: EncodeRequestToEvent(r)},
			Path:             r.URL.Path,
			Origin:           GetIPFromRequest(r),
			Key:              token,
		})

		// Report in health check
		ReportHealthCheckValue(k.Spec.Health, KeyFailure, "-1")

		return errors.New("Key is inactive, please renew"), 403
	}

	keyExpired := k.Spec.AuthManager.IsKeyExpired(session)

	if keyExpired {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
			"key":    token,
		}).Info("Attempted access from expired key.")

		// Fire a key expired event
		k.FireEvent(EventKeyExpired, EventKeyExpiredMeta{
			EventMetaDefault: EventMetaDefault{Message: "Attempted access from expired key."},
			Path:             r.URL.Path,
			Origin:           GetIPFromRequest(r),
			Key:              token,
		})

		// Report in health check
		ReportHealthCheckValue(k.Spec.Health, KeyFailure, "-1")

		return errors.New("Key has expired, please renew"), 401
	}

	return nil, 200
}
