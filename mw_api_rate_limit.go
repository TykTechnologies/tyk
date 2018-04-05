package main

import (
	"errors"
	"fmt"
	"net/http"

	"strconv"
	"time"

	"github.com/TykTechnologies/tyk/request"
	"github.com/TykTechnologies/tyk/user"
)

// RateLimitAndQuotaCheck will check the incomming request and key whether it is within it's quota and
// within it's rate limit, it makes use of the SessionLimiter object to do this
type RateLimitForAPI struct {
	BaseMiddleware
	keyName string
	apiSess *user.SessionState
}

func (k *RateLimitForAPI) Name() string {
	return "RateLimitForAPI"
}

func (k *RateLimitForAPI) EnabledForSpec() bool {
	if k.Spec.DisableRateLimit || k.Spec.GlobalRateLimit.Rate == 0 {
		return false
	}

	// We'll init here
	k.keyName = fmt.Sprintf("apilimiter-%s%s", k.Spec.OrgID, k.Spec.APIID)

	// Set last updated on each load to ensure we always use a new rate limit bucket
	k.apiSess = &user.SessionState{
		Rate:        k.Spec.GlobalRateLimit.Rate,
		Per:         k.Spec.GlobalRateLimit.Per,
		LastUpdated: strconv.Itoa(int(time.Now().UnixNano())),
	}

	return true
}

func (k *RateLimitForAPI) handleRateLimitFailure(r *http.Request, token string) (error, int) {
	logEntry := getLogEntryForRequest(r, token, nil)
	logEntry.Info("API rate limit exceeded.")

	// Fire a rate limit exceeded event
	k.FireEvent(EventRateLimitExceeded, EventKeyFailureMeta{
		EventMetaDefault: EventMetaDefault{Message: "API Rate Limit Exceeded", OriginatingRequest: EncodeRequestToEvent(r)},
		Path:             r.URL.Path,
		Origin:           request.RealIP(r),
		Key:              token,
	})

	// Report in health check
	reportHealthValue(k.Spec, Throttle, "-1")

	return errors.New("API Rate limit exceeded"), 429
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *RateLimitForAPI) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	storeRef := k.Spec.SessionManager.Store()
	reason := sessionLimiter.ForwardMessage(k.apiSess,
		k.keyName,
		storeRef,
		true,
		false,
		k.Spec.GlobalConfig,
	)

	if reason == sessionFailRateLimit {
		return k.handleRateLimitFailure(r, k.keyName)
	}

	// Request is valid, carry on
	return nil, 200
}
