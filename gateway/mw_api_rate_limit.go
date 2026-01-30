package gateway

import (
	"fmt"
	"net/http"

	"strconv"
	"time"

	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/httpctx"
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

// getOriginalPathSession returns the rate limit session for the original request path
// (before JSON-RPC routing). This is used for MCP APIs to check operation-level rate limits
// on the original endpoint in addition to tool-level rate limits on VEM paths.
// If no operation-level rate limit is found, it falls back to the global API rate limit.
func (k *RateLimitForAPI) getOriginalPathSession(r *http.Request) *user.SessionState {
	// Get the original path from JSON-RPC context if available
	rpcData := httpctx.GetJSONRPCRequest(r)
	if rpcData == nil || rpcData.VEMPath == "" {
		return nil // Not a JSON-RPC routed request
	}

	// If we're at a VEM path (routed), check for rate limits on the listen path
	// The listen path is where the original request arrived
	versionInfo, _ := k.Spec.Version(r)
	versionPaths := k.Spec.RxPaths[versionInfo.Name]

	// Look for rate limits matching the listenPath with POST method
	listenPath := k.Spec.Proxy.ListenPath
	if listenPath == "" {
		return nil
	}

	// Search for a rate limit that matches the listen path (operation-level)
	for _, vPath := range versionPaths {
		if vPath.RateLimit.Path == listenPath && vPath.RateLimit.Method == "POST" {
			limits := vPath.RateLimit
			if limits.Valid() {
				// track per-endpoint with a hash of the path
				keyname := k.keyName + "-original-" + storage.HashStr(fmt.Sprintf("%s:%s", limits.Method, limits.Path))

				session := &user.SessionState{
					Rate:        limits.Rate,
					Per:         limits.Per,
					LastUpdated: k.apiSess.LastUpdated,
				}
				session.SetKeyHash(storage.HashKey(keyname, k.Gw.GetConfig().HashKeys))

				return session
			}
		}
	}

	// If no operation-level rate limit found, return the global API rate limit
	// This ensures that global rate limits are enforced even when tool-level limits exist
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

	// Check rate limit for the current path (VEM path after routing, or original path if no routing)
	currentSession := k.getSession(r)
	reason := k.Gw.SessionLimiter.ForwardMessage(
		r,
		currentSession,
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
		return k.handleRateLimitFailure(r, event.RateLimitExceeded, "API Rate Limit Exceeded", k.keyName)
	}

	// For MCP APIs with JSON-RPC routing, also check rate limit on the original path
	// (before routing). This ensures operation-level rate limits are enforced in addition
	// to tool-level rate limits. Only do this if the current session is NOT the global session
	// (i.e., there's a tool-level rate limit being used).
	if currentSession != k.apiSess {
		if origSession := k.getOriginalPathSession(r); origSession != nil {
			origKeyName := k.keyName + "-original"
			reason := k.Gw.SessionLimiter.ForwardMessage(
				r,
				origSession,
				origKeyName,
				k.quotaKey,
				storeRef,
				true,
				false,
				k.Spec,
				false,
			)

			k.emitRateLimitEvents(r, origKeyName)

			if reason == sessionFailRateLimit {
				return k.handleRateLimitFailure(r, event.RateLimitExceeded, "API Rate Limit Exceeded", origKeyName)
			}
		}
	}

	// Request is valid, carry on
	return nil, http.StatusOK
}
