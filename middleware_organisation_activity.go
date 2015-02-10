package main

import "net/http"

import (
	"errors"
	"github.com/Sirupsen/logrus"
)

// RateLimitAndQuotaCheck will check the incomming request and key whether it is within it's quota and
// within it's rate limit, it makes use of the SessionLimiter object to do this
type OrganizationMonitor struct {
	TykMiddleware
}

// New lets you do any initialisations for the object can be done here
func (k *OrganizationMonitor) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (k *OrganizationMonitor) GetConfig() (interface{}, error) {
	return nil, nil
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *OrganizationMonitor) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	sessionLimiter := SessionLimiter{}

	thisOrg := k.Spec.OrgID
	thisSessionState, found := k.GetOrgSession(thisOrg)

	if !found {
		// No organisation session has been created, should not be a pre-requisite in site setups, so we pass the request on
		return nil, 200
	}

	// IOs it active?
	if thisSessionState.IsInactive {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": r.RemoteAddr,
			"key":    thisOrg,
		}).Info("Organisation access is disabled.")

		return errors.New("This organisation access has been disabled, please contact your API administrator."), 403
	}

	// We found a session, apply the quota limiter
	storeRef := k.Spec.OrgSessionManager.GetStore()
	forwardMessage, reason := sessionLimiter.ForwardMessage(&thisSessionState, thisOrg, storeRef)

	k.Spec.OrgSessionManager.UpdateSession(thisOrg, thisSessionState, 0)

	if !forwardMessage {
		if reason == 2 {
			log.WithFields(logrus.Fields{
				"path":   r.URL.Path,
				"origin": r.RemoteAddr,
				"key":    thisOrg,
			}).Info("Organisation quota has been exceeded.")

			// Fire a quota exceeded event
			go k.TykMiddleware.FireEvent(EVENT_OrgQuotaExceeded,
				EVENT_QuotaExceededMeta{
					EventMetaDefault: EventMetaDefault{Message: "Organisation quota has been exceeded", OriginatingRequest: EncodeRequestToEvent(r)},
					Path:             r.URL.Path,
					Origin:           r.RemoteAddr,
					Key:              thisOrg,
				})

			return errors.New("This organisation quota has been exceeded, please contact your API administrator"), 403
		}
	}

	// Request is valid, carry on
	return nil, 200
}
