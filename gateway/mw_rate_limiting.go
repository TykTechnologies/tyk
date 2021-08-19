package gateway

import (
	"errors"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

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
	k.Logger().WithField("key", obfuscateKey(token)).Info("Key rate limit exceeded.")

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
	k.Logger().WithField("key", obfuscateKey(token)).Info("Key quota limit exceeded.")

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
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	// Skip rate limiting and quotas for looping
	if !ctxCheckLimits(r) {
		return nil, http.StatusOK
	}

	session := ctxGetSession(r)
	token := ctxGetAuthToken(r)

	storeRef := GlobalSessionManager.Store()
	reason := sessionLimiter.ForwardMessage(
		r,
		session,
		token,
		storeRef,
		!k.Spec.DisableRateLimit,
		!k.Spec.DisableQuota,
		&k.Spec.GlobalConfig,
		k.Spec,
		false,
	)

	throttleRetryLimit := session.ThrottleRetryLimit
	throttleInterval := session.ThrottleInterval

	if len(session.AccessRights) > 0 {
		if rights, ok := session.AccessRights[k.Spec.APIID]; ok {
			if !rights.Limit.IsEmpty() {
				throttleInterval = rights.Limit.ThrottleInterval
				throttleRetryLimit = rights.Limit.ThrottleRetryLimit
			}
		}
	}

	switch reason {
	case sessionFailNone:
	case sessionFailRateLimit:
		err, errCode := k.handleRateLimitFailure(r, token)
		if throttleRetryLimit > 0 {
			for {
				ctxIncThrottleLevel(r, throttleRetryLimit)
				time.Sleep(time.Duration(throttleInterval * float64(time.Second)))

				reason = sessionLimiter.ForwardMessage(
					r,
					session,
					token,
					storeRef,
					!k.Spec.DisableRateLimit,
					!k.Spec.DisableQuota,
					&k.Spec.GlobalConfig,
					k.Spec,
					true,
				)

				log.WithFields(logrus.Fields{
					"middleware": "RateLimitAndQuotaCheck",
					"func":       "ProcessRequest",
				}).Debugf("after dry-run (reason: '%s')", reason)

				if ctxThrottleLevel(r) > throttleRetryLimit {
					break
				}

				if reason == sessionFailNone {
					return k.ProcessRequest(w, r, nil)
				}
			}
		}
		return err, errCode

	case sessionFailQuota:
		return k.handleQuotaFailure(r, token)
	case sessionFailInternalServerError:
		return errors.New("there was a problem proxying the request"), http.StatusInternalServerError
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
