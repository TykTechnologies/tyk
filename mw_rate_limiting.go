package main

import (
	"errors"
	"net/http"

	"github.com/TykTechnologies/tyk/request"
)

var sessionLimiter = SessionLimiter{}
var sessionMonitor = Monitor{}

// RateLimitAndQuotaCheck will check the incomming request and key whether it is within it's quota and
// within it's rate limit, it makes use of the SessionLimiter object to do this
type RateLimitAndQuotaCheck struct {
	BaseMiddleware
}

func (k *RateLimitAndQuotaCheck) Name() string {
	return "RateLimitAndQuotaCheck"
}

func (k *RateLimitAndQuotaCheck) EnabledForSpec() bool {
	return !k.Spec.DisableRateLimit || !k.Spec.DisableQuota
}

func (k *RateLimitAndQuotaCheck) handleRateLimitFailure(r *http.Request, token string) (error, int) {
	logEntry := getLogEntryForRequest(r, token, nil)
	logEntry.Info("Key rate limit exceeded.")

	// Fire a rate limit exceeded event
	k.FireEvent(EventRateLimitExceeded, EventKeyFailureMeta{
		EventMetaDefault: EventMetaDefault{Message: "Key Rate Limit Exceeded", OriginatingRequest: EncodeRequestToEvent(r)},
		Path:             r.URL.Path,
		Origin:           request.RealIP(r),
		Key:              token,
	})

	// Report in health check
	reportHealthValue(k.Spec, Throttle, "-1")

	return errors.New("Rate limit exceeded"), http.StatusTooManyRequests
}

func (k *RateLimitAndQuotaCheck) handleQuotaFailure(r *http.Request, token string) (error, int) {
	logEntry := getLogEntryForRequest(r, token, nil)
	logEntry.Info("Key quota limit exceeded.")

	// Fire a quota exceeded event
	k.FireEvent(EventQuotaExceeded, EventKeyFailureMeta{
		EventMetaDefault: EventMetaDefault{Message: "Key Quota Limit Exceeded", OriginatingRequest: EncodeRequestToEvent(r)},
		Path:             r.URL.Path,
		Origin:           request.RealIP(r),
		Key:              token,
	})

	// Report in health check
	reportHealthValue(k.Spec, QuotaViolation, "-1")

	return errors.New("Quota exceeded"), http.StatusForbidden
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *RateLimitAndQuotaCheck) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	session := ctxGetSession(r)
	token := ctxGetAuthToken(r)

	storeRef := k.Spec.SessionManager.Store()
	reason := sessionLimiter.ForwardMessage(
		r,
		session,
		token,
		storeRef,
		!k.Spec.DisableRateLimit,
		!k.Spec.DisableQuota,
		&k.Spec.GlobalConfig,
	)

	switch reason {
	case sessionFailNone:
	case sessionFailRateLimit:
		return k.handleRateLimitFailure(r, token)
	case sessionFailQuota:
		return k.handleQuotaFailure(r, token)
	default:
		// Other reason? Still not allowed
		return errors.New("Access denied"), http.StatusForbidden
	}
	// Run the trigger monitor
	if k.Spec.GlobalConfig.Monitor.MonitorUserKeys {
		sessionMonitor.Check(session, token)
	}

	// Request is valid, carry on
	return nil, http.StatusOK
}
