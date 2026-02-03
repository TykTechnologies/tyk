package gateway

import (
	"fmt"
	"net/http"

	"strconv"
	"time"

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

	if k.hasPerEndpointRateLimits() {
		return true
	}

	return k.hasValidGlobalRateLimit()
}

func (k *RateLimitForAPI) hasPerEndpointRateLimits() bool {
	for _, version := range k.Spec.VersionData.Versions {
		for _, v := range version.ExtendedPaths.RateLimit {
			if !v.Disabled {
				return true
			}
		}
	}
	return false
}

func (k *RateLimitForAPI) hasValidGlobalRateLimit() bool {
	return k.Spec.GlobalRateLimit.Rate > 0 && !k.Spec.GlobalRateLimit.Disabled
}

// getSession returns the rate limit session and keyname for the request.
// If a per-endpoint rate limit matches the request path, it returns a session
// with that limit and a unique keyname for independent tracking.
// Otherwise, it returns the global API rate limit session and keyname.
// Both return values must be used together to ensure correct rate limit tracking.
func (k *RateLimitForAPI) getSession(r *http.Request) (*user.SessionState, string) {
	versionInfo, _ := k.Spec.Version(r)
	versionPaths := k.Spec.RxPaths[versionInfo.Name]

	spec, ok := k.Spec.FindSpecMatchesStatus(r, versionPaths, RateLimit)
	if ok {
		if limits := spec.RateLimit; limits.Valid() {
			// Track per-endpoint rate limits with a unique key based on method:path hash.
			// This ensures each endpoint has independent rate limit tracking in Redis.
			keyname := k.keyName + "-" + storage.HashStr(fmt.Sprintf("%s:%s", limits.Method, limits.Path))

			session := &user.SessionState{
				Rate:        limits.Rate,
				Per:         limits.Per,
				LastUpdated: k.apiSess.LastUpdated,
			}
			session.SetKeyHash(storage.HashKey(keyname, k.Gw.GetConfig().HashKeys))

			return session, keyname
		}
	}

	// No per-endpoint limit found, use global API rate limit.
	return k.apiSess, k.keyName
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
	checkLimits := ctxCheckLimits(r)
	if !checkLimits {
		return nil, http.StatusOK
	}

	storeRef := k.Gw.GlobalSessionManager.Store()

	// Get both the session and keyname - both are required for correct rate limit tracking.
	// The keyname determines which Redis bucket is used for rate limiting.
	session, keyName := k.getSession(r)

	reason := k.Gw.SessionLimiter.ForwardMessage(
		r,
		session,
		keyName,
		k.quotaKey,
		storeRef,
		true,
		false,
		k.Spec,
		false,
	)

	k.emitRateLimitEvents(r, keyName)

	if reason == sessionFailRateLimit {
		return k.handleRateLimitFailure(r, event.RateLimitExceeded, "API Rate Limit Exceeded", keyName)
	}

	// Request is valid, carry on
	return nil, http.StatusOK
}
