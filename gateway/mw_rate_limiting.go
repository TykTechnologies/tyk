package gateway

import (
	"errors"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/ctx"
	tykerrors "github.com/TykTechnologies/tyk/internal/errors"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/request"
)

// RateLimitAndQuotaCheck will check the incomming request and key whether it is within it's quota and
// within it's rate limit, it makes use of the SessionLimiter object to do this
type RateLimitAndQuotaCheck struct {
	*BaseMiddleware
}

func (k *RateLimitAndQuotaCheck) Name() string {
	return "RateLimitAndQuotaCheck"
}

func (k *RateLimitAndQuotaCheck) EnabledForSpec() bool {
	return !k.Spec.DisableRateLimit || !k.Spec.DisableQuota
}

func (k *RateLimitAndQuotaCheck) handleQuotaFailure(r *http.Request, token string) (error, int) {
	k.Logger().WithField("key", k.Gw.obfuscateKey(token)).Info("Key quota limit exceeded.")

	// Set error classification for access logs
	ctx.SetErrorClassification(r, tykerrors.ClassifyQuotaExceededError(k.Name()))

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
	rateLimitKey := ctxGetAuthToken(r)
	quotaKey := ""

	if pattern, found := session.MetaData["rate_limit_pattern"]; found {
		if patternString, ok := pattern.(string); ok && patternString != "" {
			if customKeyValue := k.Gw.ReplaceTykVariables(r, patternString, false); customKeyValue != "" {
				rateLimitKey = customKeyValue
				quotaKey = customKeyValue
			}
		}
	}

	storeRef := k.Gw.GlobalSessionManager.Store()
	reason := k.Gw.SessionLimiter.ForwardMessage(
		r,
		session,
		rateLimitKey,
		quotaKey,
		storeRef,
		!k.Spec.DisableRateLimit,
		!k.Spec.DisableQuota,
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

	k.emitRateLimitEvents(r, rateLimitKey)

	switch reason {
	case sessionFailNone:
	case sessionFailRateLimit:
		// Set error classification for access logs
		ctx.SetErrorClassification(r, tykerrors.ClassifyRateLimitError(tykerrors.ErrTypeSessionRateLimit, k.Name()))
		err, errCode := k.handleRateLimitFailure(r, event.RateLimitExceeded, "Rate Limit Exceeded", rateLimitKey)
		if throttleRetryLimit > 0 {
			for {
				ctxIncThrottleLevel(r, throttleRetryLimit)
				time.Sleep(time.Duration(throttleInterval * float64(time.Second)))

				reason = k.Gw.SessionLimiter.ForwardMessage(
					r,
					session,
					rateLimitKey,
					quotaKey,
					storeRef,
					!k.Spec.DisableRateLimit,
					!k.Spec.DisableQuota,
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
		return k.handleQuotaFailure(r, rateLimitKey)
	case sessionFailInternalServerError:
		ctx.SetErrorClassification(r, tykerrors.ClassifyRateLimitError(tykerrors.ErrTypeOtherRateLimit, k.Name()))
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	default:
		ctx.SetErrorClassification(r, tykerrors.ClassifyRateLimitError(tykerrors.ErrTypeOtherRateLimit, k.Name()))
		// Other reason? Still not allowed
		return errors.New("Access denied"), http.StatusForbidden
	}
	// Run the trigger monitor
	if k.Spec.GlobalConfig.Monitor.MonitorUserKeys {
		k.Gw.SessionMonitor.Check(session, rateLimitKey)
	}

	// Request is valid, carry on
	return nil, http.StatusOK
}
