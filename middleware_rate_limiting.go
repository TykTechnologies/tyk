package main

import (
	"errors"
	"net/http"

	"github.com/Sirupsen/logrus"
)

var sessionLimiter = SessionLimiter{}
var sessionMonitor = Monitor{}

// RateLimitAndQuotaCheck will check the incomming request and key whether it is within it's quota and
// within it's rate limit, it makes use of the SessionLimiter object to do this
type RateLimitAndQuotaCheck struct {
	*TykMiddleware
}

func (k *RateLimitAndQuotaCheck) GetName() string {
	return "RateLimitAndQuotaCheck"
}

// New lets you do any initialisations for the object can be done here
func (k *RateLimitAndQuotaCheck) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (k *RateLimitAndQuotaCheck) GetConfig() (interface{}, error) {
	return nil, nil
}

func (k *RateLimitAndQuotaCheck) IsEnabledForSpec() bool {
	return !k.TykMiddleware.Spec.DisableRateLimit || !k.TykMiddleware.Spec.DisableQuota
}

func (k *RateLimitAndQuotaCheck) handleRateLimitFailure(r *http.Request, token string) (error, int) {
	log.WithFields(logrus.Fields{
		"path":   r.URL.Path,
		"origin": GetIPFromRequest(r),
		"key":    token,
	}).Info("Key rate limit exceeded.")

	// Fire a rate limit exceeded event
	k.TykMiddleware.FireEvent(EventRateLimitExceeded, EventRateLimitExceededMeta{
		EventMetaDefault: EventMetaDefault{Message: "Key Rate Limit Exceeded", OriginatingRequest: EncodeRequestToEvent(r)},
		Path:             r.URL.Path,
		Origin:           GetIPFromRequest(r),
		Key:              token,
	})

	// Report in health check
	ReportHealthCheckValue(k.Spec.Health, Throttle, "-1")

	return errors.New("Rate limit exceeded"), 429
}

func (k *RateLimitAndQuotaCheck) handleQuotaFailure(r *http.Request, token string) (error, int) {
	log.WithFields(logrus.Fields{
		"path":   r.URL.Path,
		"origin": GetIPFromRequest(r),
		"key":    token,
	}).Info("Key quota limit exceeded.")

	// Fire a quota exceeded event
	k.TykMiddleware.FireEvent(EventQuotaExceeded, EventQuotaExceededMeta{
		EventMetaDefault: EventMetaDefault{Message: "Key Quota Limit Exceeded", OriginatingRequest: EncodeRequestToEvent(r)},
		Path:             r.URL.Path,
		Origin:           GetIPFromRequest(r),
		Key:              token,
	})

	// Report in health check
	ReportHealthCheckValue(k.Spec.Health, QuotaViolation, "-1")

	return errors.New("Quota exceeded"), 403
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *RateLimitAndQuotaCheck) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	session := ctxGetSession(r)
	token := ctxGetAuthToken(r)

	storeRef := k.Spec.SessionManager.GetStore()
	forwardMessage, reason := sessionLimiter.ForwardMessage(session,
		token,
		storeRef,
		!k.Spec.DisableRateLimit,
		!k.Spec.DisableQuota)

	// If either are disabled, save the write roundtrip
	if !k.Spec.DisableRateLimit || !k.Spec.DisableQuota {
		// Ensure quota and rate data for this session are recorded
		if !config.UseAsyncSessionWrite {
			k.Spec.SessionManager.UpdateSession(token, session, getLifetime(k.Spec, session))
			ctxSetSession(r, session)
		} else {
			go k.Spec.SessionManager.UpdateSession(token, session, getLifetime(k.Spec, session))
			go ctxSetSession(r, session)
		}
	}

	log.Debug("SessionState: ", session)

	if !forwardMessage {
		// TODO Use an Enum!
		switch reason {
		case 1:
			return k.handleRateLimitFailure(r, token)
		case 2:
			return k.handleQuotaFailure(r, token)
		default:
			// Other reason? Still not allowed
			return errors.New("Access denied"), 403
		}
	}
	// Run the trigger monitor
	if config.Monitor.MonitorUserKeys {
		sessionMonitor.Check(session, token)
	}

	// Request is valid, carry on
	return nil, 200
}
