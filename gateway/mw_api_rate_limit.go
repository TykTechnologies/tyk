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

// getAllVEMChainSessions returns rate limit sessions for all paths in the VEM chain.
// For MCP APIs with JSON-RPC routing, this checks operation-level and tool-level rate limits sequentially.
func (k *RateLimitForAPI) getAllVEMChainSessions(r *http.Request) []*user.SessionState {
	// Check if this is a JSON-RPC routed request with a VEM chain
	rpcData := httpctx.GetJSONRPCRequest(r)
	if rpcData == nil || len(rpcData.VEMChain) == 0 {
		// Not a JSON-RPC request or no VEM chain, use normal logic
		return []*user.SessionState{k.getSession(r)}
	}

	// Check rate limits for each VEM in the chain
	versionInfo, _ := k.Spec.Version(r)
	versionPaths := k.Spec.RxPaths[versionInfo.Name]
	method := http.MethodPost // JSON-RPC always uses POST

	var sessions []*user.SessionState
	for _, vemPath := range rpcData.VEMChain {
		// Find rate limit for this VEM path
		for i := range versionPaths {
			if versionPaths[i].Status != RateLimit {
				continue
			}
			if !versionPaths[i].matchesMethod(method) {
				continue
			}

			limits := versionPaths[i].RateLimit
			if limits.Path == vemPath && limits.Method == method && limits.Valid() {
				// Create session for this rate limit
				keyname := k.keyName + "-" + storage.HashStr(fmt.Sprintf("%s:%s", limits.Method, limits.Path))

				session := &user.SessionState{
					Rate:        limits.Rate,
					Per:         limits.Per,
					LastUpdated: k.apiSess.LastUpdated,
				}
				session.SetKeyHash(storage.HashKey(keyname, k.Gw.GetConfig().HashKeys))

				sessions = append(sessions, session)
				break // Found rate limit for this VEM, move to next
			}
		}
	}

	// Always check global API rate limit if it's enabled
	// This ensures the global rate limit is enforced even when VEM-specific limits exist
	if k.apiSess.Rate > 0 {
		sessions = append(sessions, k.apiSess)
	}

	// If no sessions at all (no VEM limits and no global limit), return empty slice
	// which will skip rate limiting
	return sessions
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

	// For MCP APIs, check all rate limits in the VEM chain (operation-level + tool-level)
	// For non-MCP APIs, check only the current path rate limit
	sessions := k.getAllVEMChainSessions(r)
	for i, session := range sessions {
		keyName := k.keyName
		if i > 0 {
			keyName = fmt.Sprintf("%s-chain-%d", k.keyName, i)
		}

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
	}

	// Request is valid, carry on
	return nil, http.StatusOK
}
