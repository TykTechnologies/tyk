package main

import "net/http"

import (
	"errors"
	"github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
)

// RateLimitAndQuotaCheck will check the incomming request and key whether it is within it's quota and
// within it's rate limit, it makes use of the SessionLimiter object to do this
type RateLimitAndQuotaCheck struct {
	TykMiddleware
}

// New lets you do any initialisations for the object can be done here
func (k *RateLimitAndQuotaCheck) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (k *RateLimitAndQuotaCheck) GetConfig() (interface{}, error) {
	return nil, nil
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *RateLimitAndQuotaCheck) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	sessionLimiter := SessionLimiter{}
	thisSessionState := context.Get(r, SessionData).(SessionState)
	authHeaderValue := context.Get(r, AuthHeaderValue).(string)
	forwardMessage, reason := sessionLimiter.ForwardMessage(&thisSessionState)

	// Ensure quota and rate data for this session are recorded
	k.Spec.SessionManager.UpdateSession(authHeaderValue, thisSessionState, 0)

	log.Debug("SessionState: ", thisSessionState)

	if !forwardMessage {
		// TODO Use an Enum!
		if reason == 1 {
			log.WithFields(logrus.Fields{
				"path":   r.URL.Path,
				"origin": r.RemoteAddr,
				"key":    authHeaderValue,
			}).Info("Key rate limit exceeded.")

			return errors.New("Rate limit exceeded"), 403

		} else if reason == 2 {
			log.WithFields(logrus.Fields{
				"path":   r.URL.Path,
				"origin": r.RemoteAddr,
				"key":    authHeaderValue,
			}).Info("Key quota limit exceeded.")

			// Fire a quota exceeded event
			go k.TykMiddleware.FireEvent(EVENT_QuotaExceeded,
				EVENT_QuotaExceededMeta{
					EventMetaDefault: EventMetaDefault{Message: "Key Quota Limit Exceeded"},
					Path: r.URL.Path,
					Origin: r.RemoteAddr,
					Key: authHeaderValue,
			})

			return errors.New("Quota exceeded"), 403
		}
		// Other reason? Still not allowed
		return errors.New("Access denied"), 403
	}

	// Request is valid, carry on
	return nil, 200
}
