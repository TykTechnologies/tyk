package gateway

import (
	"fmt"
	"net/http"

	"strconv"
	"time"

	"github.com/TykTechnologies/tyk/ctx"
	tykerrors "github.com/TykTechnologies/tyk/internal/errors"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

// RateLimitForAPI will check the incoming request and key whether it is within it's quota and
// within it's rate limit, it makes use of the SessionLimiter object to do this
type RateLimitForAPI struct {
	*BaseMiddleware

	keyName  string
	quotaKey string
	apiSess  *user.SessionState
}

func (k *RateLimitForAPI) Name() string {
	return "RateLimitForAPI"
}

func (k *RateLimitForAPI) shouldEnable() bool {
	if k.Spec.DisableRateLimit {
		return false
	}

	// per endpoint rate limits
	for _, version := range k.Spec.VersionData.Versions {
		for _, v := range version.ExtendedPaths.RateLimit {
			if !v.Disabled {
				return true
			}
		}
	}

	// global api rate limit
	if k.Spec.GlobalRateLimit.Rate == 0 || k.Spec.GlobalRateLimit.Disabled {
		return false
	}

	return true
}

func (k *RateLimitForAPI) getSession(r *http.Request) *user.SessionState {
	versionInfo, _ := k.Spec.Version(r)
	versionPaths := k.Spec.RxPaths[versionInfo.Name]

	spec, ok := k.Spec.FindSpecMatchesStatus(r, versionPaths, RateLimit)
	if ok {
		if limits := spec.RateLimit; limits.Valid() {
			// track per-endpoint with a hash of the path
			keyname := k.keyName + "-" + storage.HashStr(fmt.Sprintf("%s:%s", limits.Method, limits.Path))

			session := &user.SessionState{
				Rate:        limits.Rate,
				Per:         limits.Per,
				LastUpdated: k.apiSess.LastUpdated,
			}
			session.SetKeyHash(storage.HashKey(keyname, k.Gw.GetConfig().HashKeys))

			return session
		}
	}

	return k.apiSess
}

func (k *RateLimitForAPI) EnabledForSpec() bool {
	if !k.shouldEnable() {
		return false
	}

	// We'll init here
	k.keyName = "apilimiter-" + k.Spec.OrgID + k.Spec.APIID

	// Set last updated on each load to ensure we always use a new rate limit bucket
	k.apiSess = &user.SessionState{
		Rate:        k.Spec.GlobalRateLimit.Rate,
		Per:         k.Spec.GlobalRateLimit.Per,
		LastUpdated: strconv.Itoa(int(time.Now().UnixNano())),
	}
	k.apiSess.SetKeyHash(storage.HashKey(k.keyName, k.Gw.GetConfig().HashKeys))

	return true
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *RateLimitForAPI) ProcessRequest(_ http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	// Skip rate limiting and quotas for looping
	if !ctxCheckLimits(r) {
		return nil, http.StatusOK
	}

	storeRef := k.Gw.GlobalSessionManager.Store()

	reason := k.Gw.SessionLimiter.ForwardMessage(
		r,
		k.getSession(r),
		k.keyName,
		k.quotaKey,
		storeRef,
		true,
		false,
		k.Spec,
		false,
	)

	k.emitRateLimitEvents(r, k.keyName)

	if reason == sessionFailRateLimit {
		// Set error classification for access logs
		ctx.SetErrorClassification(r, tykerrors.ClassifyRateLimitError(tykerrors.ErrTypeAPIRateLimit, k.Name()))
		return k.handleRateLimitFailure(r, event.RateLimitExceeded, "API Rate Limit Exceeded", k.keyName)
	}

	// Request is valid, carry on
	return nil, http.StatusOK
}
