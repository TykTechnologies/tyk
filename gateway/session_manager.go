package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/regexp"

	"github.com/TykTechnologies/drl"
	"github.com/TykTechnologies/leakybucket"
	"github.com/TykTechnologies/leakybucket/memorycache"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/rate"
	"github.com/TykTechnologies/tyk/internal/redis"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
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
	// QuotaKeyPrefix serves as a standard prefix for generating quota keys.
	QuotaKeyPrefix = "quota-"

	// RateLimitKeyPrefix serves as a standard prefix for generating rate limiter keys.
	RateLimitKeyPrefix = rate.LimiterKeyPrefix

	// SentinelRateLimitKeyPostfix is appended to the rate limiting key to combine into a sentinel key.
	SentinelRateLimitKeyPostfix = ".BLOCKED"
)

// SessionLimiter is the rate limiter for the API, use ForwardMessage() to
// check if a message should pass through or not
type SessionLimiter struct {
	ctx            context.Context
	drlManager     *drl.DRL
	config         *config.Config
	bucketStore    leakybucket.Storage
	limiterStorage redis.UniversalClient
	smoothing      *rate.Smoothing
}

// NewSessionLimiter initializes the session limiter.
//
// The session limiter initializes the storage required for rate limiters.
// It supports two storage types: `redis` and `local`. If redis storage is
// configured, then redis will be used. If local storage is configured, then
// in-memory counters will be used. If no storage is configured, it falls
// back onto the default gateway storage configuration.
func NewSessionLimiter(ctx context.Context, conf *config.Config, drlManager *drl.DRL) SessionLimiter {
	sessionLimiter := SessionLimiter{
		ctx:         ctx,
		drlManager:  drlManager,
		config:      conf,
		bucketStore: memorycache.New(),
	}

	log.Infof("[RATELIMIT] %s", conf.RateLimit.String())

	storageConf := conf.GetRateLimiterStorage()

	switch storageConf.Type {
	case "redis":
		sessionLimiter.limiterStorage = rate.NewStorage(storageConf)
	}

	sessionLimiter.smoothing = rate.NewSmoothing(sessionLimiter.limiterStorage)

	return sessionLimiter
}

func (l *SessionLimiter) Context() context.Context {
	return l.ctx
}

func (l *SessionLimiter) doRollingWindowWrite(r *http.Request, session *user.SessionState, rateLimiterKey string, apiLimit *user.APILimit, dryRun bool) bool {
	ctx := l.Context()
	rateLimiterSentinelKey := rateLimiterKey + SentinelRateLimitKeyPostfix

	var per, cost float64

	if apiLimit != nil { // respect limit on API level
		per = apiLimit.Per
		cost = apiLimit.Rate
	}

	pipeline := l.config.EnableNonTransactionalRateLimiter

	smoothingFn := func(_ context.Context, key string, currentRate, maxAllowedRate int64) bool {
		// Subtract by 1 because of the delayed add in the window
		var subtractor int64 = 1
		if l.config.EnableSentinelRateLimiter || l.config.DRLEnableSentinelRateLimiter {
			// and another subtraction because of the preemptive limit
			subtractor = 2
		}

		allowedRate := maxAllowedRate

		// Smoothing of the defined rate limits
		if l.config.EnableRateLimitSmoothing {
			smoothingConf := session.Smoothing
			if apiLimit != nil && apiLimit.Smoothing.Valid() {
				smoothingConf = apiLimit.Smoothing
			}

			if smoothingConf.Valid() {
				// Do rate limit smoothing
				allowance, err := l.smoothing.Do(r, smoothingConf, key, currentRate, maxAllowedRate)

				// If smoothing change returned any error, log it.
				if err != nil {
					log.Warn(err)
				}

				// Use provided allowance
				if allowance != nil {
					allowedRate = allowance.Get()
				}
			}
		}

		return currentRate > allowedRate-subtractor
	}

	ratelimit := rate.NewSlidingLogRedis(l.limiterStorage, pipeline, smoothingFn)
	shouldBlock, err := ratelimit.Do(ctx, time.Now(), rateLimiterKey, int64(cost), int64(per))
	if shouldBlock {
		// Set a sentinel value with expire
		if l.config.EnableSentinelRateLimiter || l.config.DRLEnableSentinelRateLimiter {
			if !dryRun {
				l.limiterStorage.SetNX(ctx, rateLimiterSentinelKey, "1", time.Second*time.Duration(int64(per)))
			}
		}
	}

	if err != nil {
		log.WithError(err).Error("error writing sliding log")
	}

	return shouldBlock
}

type sessionFailReason uint

const (
	sessionFailNone sessionFailReason = iota
	sessionFailRateLimit
	sessionFailQuota
	sessionFailInternalServerError
)

func (l *SessionLimiter) limitSentinel(r *http.Request, session *user.SessionState, rateLimiterKey string, apiLimit *user.APILimit, dryRun bool) bool {
	defer func() {
		go l.doRollingWindowWrite(r, session, rateLimiterKey, apiLimit, dryRun)
	}()

	// Check sentinel
	_, sentinelActive := l.limiterStorage.Get(l.Context(), rateLimiterKey+SentinelRateLimitKeyPostfix).Result()

	// Sentinel is set, fail
	return sentinelActive == nil
}

func (l *SessionLimiter) limitRedis(r *http.Request, session *user.SessionState, rateLimiterKey string, apiLimit *user.APILimit, dryRun bool) bool {
	return l.doRollingWindowWrite(r, session, rateLimiterKey, apiLimit, dryRun)
}

func (l *SessionLimiter) limitDRL(bucketKey string, apiLimit *user.APILimit, dryRun bool) bool {
	currRate := apiLimit.Rate
	per := apiLimit.Per

	tokenValue := uint(l.drlManager.CurrentTokenValue())

	// DRL will always overflow with more servers on low rates
	cost := uint(currRate * float64(l.drlManager.RequestTokenValue))
	if cost < tokenValue {
		cost = tokenValue
	}

	userBucket, err := l.bucketStore.Create(bucketKey, cost, time.Duration(per)*time.Second)
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
		_, errF := userBucket.Add(tokenValue)
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
func (l *SessionLimiter) ForwardMessage(r *http.Request, session *user.SessionState, rateLimitKey string, quotaKey string, store storage.Handler, enableRL, enableQ bool, api *APISpec, dryRun bool) sessionFailReason {
	// check for limit on API level (set to session by ApplyPolicies)
	accessDef, allowanceScope, err := GetAccessDefinitionByAPIIDOrSession(session, api)
	if err != nil {
		log.WithField("apiID", api.APIID).Debugf("[RATE] %s", err.Error())
		return sessionFailRateLimit
	}

	var (
		apiLimit            = accessDef.Limit.Clone()
		endpointRLKeySuffix = ""
	)

	if len(accessDef.Endpoints) > 0 {
		endpointRLInfo, doEndpointRL := getEndpointRateLimitInfo(r.Method, r.URL.Path, accessDef.Endpoints)
		if doEndpointRL {
			apiLimit.Rate = float64(endpointRLInfo.rate)
			apiLimit.Per = float64(endpointRLInfo.per)
			endpointRLKeySuffix = endpointRLInfo.keySuffix
		}
	}

	// If quotaKey is not set then the default ratelimit keys should be used.
	useCustomKey := quotaKey != ""

	// If rate is -1 or 0, it means unlimited and no need for rate limiting.
	if enableRL && apiLimit.Rate > 0 {
		log.Debug("[RATELIMIT] Inbound raw key is: ", rateLimitKey)

		// This limiter key should be used consistently here out.
		limiterKey := rate.LimiterKey(session, allowanceScope, rateLimitKey, useCustomKey)

		if endpointRLKeySuffix != "" {
			log.Debugf("[RATELIMIT] applying endpoint rate limit key suffix: %s: %s", limiterKey, endpointRLKeySuffix)
			limiterKey = rate.Prefix(limiterKey, endpointRLKeySuffix)
		}

		log.Debug("[RATELIMIT] Rate limiter key is: ", limiterKey)

		limiter := rate.Limiter(l.config, l.limiterStorage)

		switch {
		case limiter != nil:
			err := limiter(r.Context(), limiterKey, apiLimit.Rate, apiLimit.Per)

			if errors.Is(err, rate.ErrLimitExhausted) {
				return sessionFailRateLimit
			}

		case l.config.EnableSentinelRateLimiter:
			if l.limitSentinel(r, session, limiterKey, &apiLimit, dryRun) {
				return sessionFailRateLimit
			}
		case l.config.EnableRedisRollingLimiter:
			if l.limitRedis(r, session, limiterKey, &apiLimit, dryRun) {
				return sessionFailRateLimit
			}
		default:
			var n float64
			if l.drlManager.Servers != nil {
				n = float64(l.drlManager.Servers.Count())
			}
			cost := apiLimit.Rate / apiLimit.Per
			c := l.config.DRLThreshold
			if c == 0 {
				// defaults to 5
				c = 5
			}

			if n <= 1 || n*c < cost {
				// If we have 1 server, there is no need to strain redis at all the leaky
				// bucket algorithm will suffice.

				bucketKey := limiterKey + ":" + session.LastUpdated
				if useCustomKey {
					bucketKey = limiterKey
				}

				if l.limitDRL(bucketKey, &apiLimit, dryRun) {
					return sessionFailRateLimit
				}
			} else {
				if l.limitRedis(r, session, limiterKey, &apiLimit, dryRun) {
					return sessionFailRateLimit
				}
			}
		}
	}

	if enableQ {
		if l.config.LegacyEnableAllowanceCountdown {
			session.Allowance = session.Allowance - 1
		}

		if l.RedisQuotaExceeded(r, session, quotaKey, allowanceScope, &apiLimit, store, l.config.HashKeys) {
			return sessionFailQuota
		}
	}

	return sessionFailNone

}

func (l *SessionLimiter) RedisQuotaExceeded(r *http.Request, session *user.SessionState, quotaKey, scope string, limit *user.APILimit, store storage.Handler, hashKeys bool) bool {
	// Unlimited?
	if limit.QuotaMax == -1 || limit.QuotaMax == 0 {
		// No quota set
		return false
	}

	session.Touch()

	quotaScope := ""
	if scope != "" {
		quotaScope = scope + "-"
	}

	key := session.KeyID

	if hashKeys {
		key = storage.HashStr(session.KeyID)
	}

	if quotaKey != "" {
		key = quotaKey
	}

	rawKey := QuotaKeyPrefix + quotaScope + key
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
		log.Debug("Session: ", session)
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
	}

	// If not, pass and set the values of the session to quotamax - counter
	remaining := quotaMax - qInt
	if remaining < 0 {
		remaining = 0
	}

	for k, v := range session.AccessRights {
		if v.Limit.IsEmpty() {
			continue
		}

		if v.AllowanceScope == scope {
			v.Limit.QuotaRemaining = remaining
			v.Limit.QuotaRenews = quotaRenews
		}
		session.AccessRights[k] = v
	}

	if scope == "" {
		session.QuotaRemaining = remaining
		session.QuotaRenews = quotaRenews
	}

	return false
}

func GetAccessDefinitionByAPIIDOrSession(session *user.SessionState, api *APISpec) (accessDef *user.AccessDefinition, allowanceScope string, err error) {
	accessDef = &user.AccessDefinition{}
	if len(session.AccessRights) > 0 {
		if rights, ok := session.AccessRights[api.APIID]; !ok {
			return nil, "", errors.New("unexpected apiID")
		} else {
			accessDef.Limit = rights.Limit
			accessDef.FieldAccessRights = rights.FieldAccessRights
			accessDef.RestrictedTypes = rights.RestrictedTypes
			accessDef.AllowedTypes = rights.AllowedTypes
			accessDef.DisableIntrospection = rights.DisableIntrospection
			accessDef.Endpoints = rights.Endpoints
			allowanceScope = rights.AllowanceScope
		}
	}
	if accessDef.Limit.IsEmpty() {
		accessDef.Limit = session.APILimit()
	}

	return accessDef, allowanceScope, nil
}

type endpointRateLimitInfo struct {
	keySuffix string
	rate      int64
	per       int64
}

func getEndpointRateLimitInfo(method string, path string, endpoints []user.Endpoint) (*endpointRateLimitInfo, bool) {
	for _, endpoint := range endpoints {
		asRegex, err := regexp.Compile(endpoint.Path)
		if err != nil {
			return nil, false
		}

		match := asRegex.MatchString(path)
		if match {
			for _, endpointMethod := range endpoint.Methods {
				if strings.ToUpper(endpointMethod.Name) == strings.ToUpper(method) {
					return &endpointRateLimitInfo{
						keySuffix: storage.HashStr(fmt.Sprintf("%s:%s", endpointMethod.Name, endpoint.Path)),
						rate:      endpointMethod.Limit.Rate,
						per:       endpointMethod.Limit.Per,
					}, true
				}
			}
		}
	}

	return nil, false
}
