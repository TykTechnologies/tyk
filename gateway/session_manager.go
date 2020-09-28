package gateway

import (
	"fmt"
	"net/http"
	"time"

	"github.com/jensneuse/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/leakybucket"
	"github.com/TykTechnologies/leakybucket/memorycache"
	"github.com/TykTechnologies/tyk/v3/config"
	"github.com/TykTechnologies/tyk/v3/storage"
	"github.com/TykTechnologies/tyk/v3/user"
)

type PublicSession struct {
	Quota struct {
		QuotaMax       int64 `json:"quota_max"`
		QuotaRemaining int64 `json:"quota_remaining"`
		QuotaRenews    int64 `json:"quota_renews"`
	} `json:"quota"`
	RateLimit struct {
		Rate float64 `json:"requests"`
		Per  float64 `json:"per_unit"`
	} `json:"rate_limit"`
}

const (
	QuotaKeyPrefix     = "quota-"
	RateLimitKeyPrefix = "rate-limit-"
)

// SessionLimiter is the rate limiter for the API, use ForwardMessage() to
// check if a message should pass through or not
type SessionLimiter struct {
	bucketStore leakybucket.Storage
}

func (l *SessionLimiter) doRollingWindowWrite(key, rateLimiterKey, rateLimiterSentinelKey string,
	currentSession *user.SessionState,
	store storage.Handler,
	globalConf *config.Config,
	apiLimit *user.APILimit, dryRun bool) bool {

	var per, rate float64

	if apiLimit != nil { // respect limit on API level
		per = apiLimit.Per
		rate = apiLimit.Rate
	} else {
		per = currentSession.Per
		rate = currentSession.Rate
	}

	log.Debug("[RATELIMIT] Inbound raw key is: ", key)
	log.Debug("[RATELIMIT] Rate limiter key is: ", rateLimiterKey)
	pipeline := globalConf.EnableNonTransactionalRateLimiter

	var ratePerPeriodNow int
	if dryRun {
		ratePerPeriodNow, _ = store.GetRollingWindow(rateLimiterKey, int64(per), pipeline)
	} else {
		ratePerPeriodNow, _ = store.SetRollingWindow(rateLimiterKey, int64(per), "-1", pipeline)
	}

	//log.Info("Num Requests: ", ratePerPeriodNow)

	// Subtract by 1 because of the delayed add in the window
	subtractor := 1
	if globalConf.EnableSentinelRateLimiter || globalConf.DRLEnableSentinelRateLimiter {
		// and another subtraction because of the preemptive limit
		subtractor = 2
	}
	// The test TestRateLimitForAPIAndRateLimitAndQuotaCheck
	// will only work with ththese two lines here
	//log.Info("break: ", (int(currentSession.Rate) - subtractor))
	if ratePerPeriodNow > int(rate)-subtractor {
		// Set a sentinel value with expire
		if globalConf.EnableSentinelRateLimiter || globalConf.DRLEnableSentinelRateLimiter {
			if !dryRun {
				store.SetRawKey(rateLimiterSentinelKey, "1", int64(per))
			}
		}
		return true
	}

	return false
}

type sessionFailReason uint

const (
	sessionFailNone sessionFailReason = iota
	sessionFailRateLimit
	sessionFailQuota
	sessionFailDepthLimit
	sessionFailInternalServerError
)

func (l *SessionLimiter) limitSentinel(currentSession *user.SessionState, key string, rateScope string, store storage.Handler,
	globalConf *config.Config, apiLimit *user.APILimit, dryRun bool) bool {

	rateLimiterKey := RateLimitKeyPrefix + rateScope + currentSession.GetKeyHash()
	rateLimiterSentinelKey := RateLimitKeyPrefix + rateScope + currentSession.GetKeyHash() + ".BLOCKED"

	go l.doRollingWindowWrite(key, rateLimiterKey, rateLimiterSentinelKey, currentSession, store, globalConf, apiLimit, dryRun)

	// Check sentinel
	_, sentinelActive := store.GetRawKey(rateLimiterSentinelKey)
	if sentinelActive == nil {
		// Sentinel is set, fail
		return true
	}
	return false
}

func (l *SessionLimiter) limitRedis(currentSession *user.SessionState, key string, rateScope string, store storage.Handler,
	globalConf *config.Config, apiLimit *user.APILimit, dryRun bool) bool {

	rateLimiterKey := RateLimitKeyPrefix + rateScope + currentSession.GetKeyHash()
	rateLimiterSentinelKey := RateLimitKeyPrefix + rateScope + currentSession.GetKeyHash() + ".BLOCKED"

	if l.doRollingWindowWrite(key, rateLimiterKey, rateLimiterSentinelKey, currentSession, store, globalConf, apiLimit, dryRun) {
		return true
	}
	return false
}

func (l *SessionLimiter) limitDRL(currentSession *user.SessionState, key string, rateScope string,
	apiLimit *user.APILimit, dryRun bool) bool {

	// In-memory limiter
	if l.bucketStore == nil {
		l.bucketStore = memorycache.New()
	}

	bucketKey := key + ":" + rateScope + currentSession.LastUpdated
	currRate := apiLimit.Rate
	per := apiLimit.Per

	// DRL will always overflow with more servers on low rates
	rate := uint(currRate * float64(DRLManager.RequestTokenValue))
	if rate < uint(DRLManager.CurrentTokenValue()) {
		rate = uint(DRLManager.CurrentTokenValue())
	}
	userBucket, err := l.bucketStore.Create(bucketKey, rate, time.Duration(per)*time.Second)
	if err != nil {
		log.Error("Failed to create bucket!")
		return true
	}

	if dryRun {
		// if userBucket is empty and not expired.
		if userBucket.Remaining() == 0 && time.Now().Before(userBucket.Reset()) {
			return true
		}
	} else {
		_, errF := userBucket.Add(uint(DRLManager.CurrentTokenValue()))
		if errF != nil {
			return true
		}
	}
	return false
}

func (sfr sessionFailReason) String() string {
	switch sfr {
	case sessionFailNone:
		return "sessionFailNone"
	case sessionFailRateLimit:
		return "sessionFailRateLimit"
	case sessionFailQuota:
		return "sessionFailQuota"
	default:
		return fmt.Sprintf("%d", uint(sfr))
	}
}

// ForwardMessage will enforce rate limiting, returning a non-zero
// sessionFailReason if session limits have been exceeded.
// Key values to manage rate are Rate and Per, e.g. Rate of 10 messages
// Per 10 seconds
func (l *SessionLimiter) ForwardMessage(r *http.Request, currentSession *user.SessionState, key string, store storage.Handler, enableRL, enableQ bool, globalConf *config.Config, api *APISpec, dryRun bool) sessionFailReason {
	// check for limit on API level (set to session by ApplyPolicies)
	accessDef := &user.AccessDefinition{}
	var allowanceScope string

	var gqlRequest *graphql.Request
	if api.GraphQL.Enabled {
		gqlRequest = ctxGetGraphQLRequest(r)
	}

	if len(currentSession.GetAccessRights()) > 0 {
		if rights, ok := currentSession.GetAccessRightByAPIID(api.APIID); !ok {
			log.WithField("apiID", api.APIID).Debug("[RATE] unexpected apiID")
			return sessionFailRateLimit
		} else {
			accessDef.Limit = rights.Limit
			accessDef.FieldAccessRights = rights.FieldAccessRights
			allowanceScope = rights.AllowanceScope
		}
	}

	if accessDef.Limit == nil {
		accessDef = &user.AccessDefinition{
			Limit: &user.APILimit{
				QuotaMax:           currentSession.QuotaMax,
				QuotaRenewalRate:   currentSession.QuotaRenewalRate,
				QuotaRenews:        currentSession.QuotaRenews,
				Rate:               currentSession.Rate,
				Per:                currentSession.Per,
				ThrottleInterval:   currentSession.ThrottleInterval,
				ThrottleRetryLimit: currentSession.ThrottleRetryLimit,
				MaxQueryDepth:      currentSession.MaxQueryDepth,
			},
		}
	}

	// If MaxQueryDepth is -1 or 0, it means unlimited and no need for depth limiting.
	if l.DepthLimitEnabled(api.GraphQL.Enabled, accessDef) {
		if failReason := l.DepthLimitExceeded(gqlRequest, accessDef, api.GraphQLExecutor.Schema); failReason != sessionFailNone {
			return failReason
		}
	}

	// If rate is -1 or 0, it means unlimited and no need for rate limiting.
	if enableRL && accessDef.Limit.Rate > 0 {
		rateScope := ""
		if allowanceScope != "" {
			rateScope = allowanceScope + "-"
		}
		if globalConf.EnableSentinelRateLimiter {
			if l.limitSentinel(currentSession, key, rateScope, store, globalConf, accessDef.Limit, dryRun) {
				return sessionFailRateLimit
			}
		} else if globalConf.EnableRedisRollingLimiter {
			if l.limitRedis(currentSession, key, rateScope, store, globalConf, accessDef.Limit, dryRun) {
				return sessionFailRateLimit
			}
		} else {
			var n float64
			if DRLManager.Servers != nil {
				n = float64(DRLManager.Servers.Count())
			}
			rate := accessDef.Limit.Rate / accessDef.Limit.Per
			c := globalConf.DRLThreshold
			if c == 0 {
				// defaults to 5
				c = 5
			}

			if n <= 1 || n*c < rate {
				// If we have 1 server, there is no need to strain redis at all the leaky
				// bucket algorithm will suffice.
				if l.limitDRL(currentSession, key, rateScope, accessDef.Limit, dryRun) {
					return sessionFailRateLimit
				}
			} else {
				if l.limitRedis(currentSession, key, rateScope, store, globalConf, accessDef.Limit, dryRun) {
					return sessionFailRateLimit
				}
			}
		}
	}

	if enableQ {
		if globalConf.LegacyEnableAllowanceCountdown {
			currentSession.Allowance = currentSession.Allowance - 1
		}

		if l.RedisQuotaExceeded(r, currentSession, allowanceScope, accessDef.Limit, store) {
			return sessionFailQuota
		}
	}

	return sessionFailNone

}

func (l *SessionLimiter) DepthLimitEnabled(graphqlEnabled bool, accessDef *user.AccessDefinition) bool {
	if !graphqlEnabled {
		return false
	}

	// There is a possibility that depth limit is disabled on field level too,
	// but we continue with this because of the explanation above.
	if len(accessDef.FieldAccessRights) > 0 {
		return true
	}

	return accessDef.Limit.MaxQueryDepth > 0
}

func (l *SessionLimiter) DepthLimitExceeded(gqlRequest *graphql.Request, accessDef *user.AccessDefinition, schema *graphql.Schema) sessionFailReason {
	complexityRes, err := gqlRequest.CalculateComplexity(graphql.DefaultComplexityCalculator, schema)
	if err != nil {
		log.Errorf("Error while calculating complexity of GraphQL request: '%s'", err)
		return sessionFailInternalServerError
	}

	// do per query depth check
	if len(accessDef.FieldAccessRights) == 0 {
		if complexityRes.Depth > accessDef.Limit.MaxQueryDepth {
			log.Debugf("Complexity of the request is higher than the allowed limit '%d'", accessDef.Limit.MaxQueryDepth)
			return sessionFailDepthLimit
		}
		return sessionFailNone
	}

	// do per query field depth check
	for _, fieldAccessDef := range accessDef.FieldAccessRights {
		for _, fieldComplexityRes := range complexityRes.PerRootField {
			if fieldComplexityRes.TypeName != fieldAccessDef.TypeName {
				continue
			}
			if fieldComplexityRes.FieldName != fieldAccessDef.FieldName {
				continue
			}

			if greaterThanInt(fieldComplexityRes.Depth, fieldAccessDef.Limits.MaxQueryDepth) {
				log.Debugf("Complexity of the field: %s.%s is higher than the allowed limit '%d'",
					fieldAccessDef.TypeName, fieldAccessDef.FieldName, accessDef.Limit.MaxQueryDepth)

				return sessionFailDepthLimit
			}
		}
	}

	return sessionFailNone
}

func (l *SessionLimiter) RedisQuotaExceeded(r *http.Request, currentSession *user.SessionState, scope string, limit *user.APILimit, store storage.Handler) bool {
	// Unlimited?
	if limit.QuotaMax == -1 || limit.QuotaMax == 0 {
		// No quota set
		return false
	}

	quotaScope := ""
	if scope != "" {
		quotaScope = scope + "-"
	}

	rawKey := QuotaKeyPrefix + quotaScope + currentSession.GetKeyHash()
	quotaRenewalRate := limit.QuotaRenewalRate
	quotaRenews := limit.QuotaRenews
	quotaMax := limit.QuotaMax

	log.Debug("[QUOTA] Quota limiter key is: ", rawKey)
	log.Debug("Renewing with TTL: ", quotaRenewalRate)
	// INCR the key (If it equals 1 - set EXPIRE)
	qInt := store.IncrememntWithExpire(rawKey, quotaRenewalRate)
	// if the returned val is >= quota: block
	if qInt-1 >= quotaMax {
		renewalDate := time.Unix(quotaRenews, 0)
		log.Debug("Renewal Date is: ", renewalDate)
		log.Debug("As epoch: ", quotaRenews)
		log.Debug("Session: ", currentSession)
		log.Debug("Now:", time.Now())
		if time.Now().After(renewalDate) {
			//for renew quota = never, once we get the quota max we must not allow using it again

			if quotaRenewalRate <= 0 {
				return true
			}
			// The renewal date is in the past, we should update the quota!
			// Also, this fixes legacy issues where there is no TTL on quota buckets
			log.Debug("Incorrect key expiry setting detected, correcting")
			go store.DeleteRawKey(rawKey)
			qInt = 1
		} else {
			// Renewal date is in the future and the quota is exceeded
			return true
		}

	}

	// If this is a new Quota period, ensure we let the end user know
	if qInt == 1 {
		quotaRenews = time.Now().Unix() + quotaRenewalRate
		ctxScheduleSessionUpdate(r)
	}

	// If not, pass and set the values of the session to quotamax - counter
	remaining := quotaMax - qInt
	if remaining < 0 {
		remaining = 0
	}

	for k, v := range currentSession.GetAccessRights() {
		if v.Limit == nil {
			continue
		}

		if v.AllowanceScope == scope {
			v.Limit.QuotaRemaining = remaining
			v.Limit.QuotaRenews = quotaRenews
		}
		currentSession.SetAccessRight(k, v)
	}

	if scope == "" {
		currentSession.QuotaRemaining = remaining
		currentSession.QuotaRenews = quotaRenews
	}

	return false
}
