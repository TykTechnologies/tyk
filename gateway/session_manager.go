package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/drl"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/httputil"
	"github.com/TykTechnologies/tyk/internal/memorycache"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/internal/rate"
	"github.com/TykTechnologies/tyk/internal/rate/limiter"
	"github.com/TykTechnologies/tyk/internal/redis"
	"github.com/TykTechnologies/tyk/regexp"
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
	bucketStore    model.BucketStorage
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
		bucketStore: memorycache.New(ctx),
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

func (l *SessionLimiter) RateLimitInfo(r *http.Request, api *APISpec, endpoints user.Endpoints) (*user.EndpointRateLimitInfo, bool) {
	// Hook per-api settings here (m.Spec...)
	isPrefixMatch := l.config.HttpServerOptions.EnablePathPrefixMatching
	isSuffixMatch := l.config.HttpServerOptions.EnablePathSuffixMatching

	urlPaths := []string{
		api.StripListenPath(r.URL.Path),
		r.URL.Path,
	}

	for _, endpoint := range endpoints {
		if !endpoint.Methods.Contains(r.Method) {
			continue
		}

		pattern := httputil.PreparePathRegexp(endpoint.Path, isPrefixMatch, isSuffixMatch)

		asRegex, err := regexp.Compile(pattern)
		if err != nil {
			log.WithError(err).Error("endpoint rate limit: error compiling regex")
			continue
		}

		for _, urlPath := range urlPaths {
			match := asRegex.MatchString(urlPath)
			if !match {
				break
			}

			for _, endpointMethod := range endpoint.Methods {
				if !strings.EqualFold(endpointMethod.Name, r.Method) {
					continue
				}

				return &user.EndpointRateLimitInfo{
					KeySuffix: storage.HashStr(fmt.Sprintf("%s:%s", endpointMethod.Name, endpoint.Path)),
					Rate:      endpointMethod.Limit.Rate,
					Per:       endpointMethod.Limit.Per,
				}, true
			}
		}
	}
	return nil, false

}

// ForwardMessage will enforce rate limiting, returning a non-zero
// sessionFailReason if session limits have been exceeded.
// Key values to manage rate are Rate and Per, e.g. Rate of 10 messages
// Per 10 seconds
func (l *SessionLimiter) ForwardMessage(
	r *http.Request,
	session *user.SessionState,
	rateLimitKey string,
	quotaKey string,
	store storage.Handler,
	enableRL, enableQ bool,
	api *APISpec,
	dryRun bool,
) sessionFailReason {
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

	endpointRLInfo, doEndpointRL := l.RateLimitInfo(r, api, accessDef.Endpoints)
	if doEndpointRL {
		apiLimit.Rate = endpointRLInfo.Rate
		apiLimit.Per = endpointRLInfo.Per
		endpointRLKeySuffix = endpointRLInfo.KeySuffix
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
			if l.limitSentinel(r, session, limiterKey, apiLimit, dryRun) {
				return sessionFailRateLimit
			}
		case l.config.EnableRedisRollingLimiter:
			if l.limitRedis(r, session, limiterKey, apiLimit, dryRun) {
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

				if l.limitDRL(bucketKey, apiLimit, dryRun) {
					return sessionFailRateLimit
				}
			} else {
				if l.limitRedis(r, session, limiterKey, apiLimit, dryRun) {
					return sessionFailRateLimit
				}
			}
		}
	}

	if enableQ {
		if l.config.LegacyEnableAllowanceCountdown {
			session.Allowance = session.Allowance - 1
		}

		if l.RedisQuotaExceeded(r, session, quotaKey, allowanceScope, apiLimit, store, l.config.HashKeys) {
			return sessionFailQuota
		}
	}

	return sessionFailNone
}

// RedisQuotaExceeded returns true if the request should be blocked as over quota.
func (l *SessionLimiter) RedisQuotaExceeded(r *http.Request, session *user.SessionState, quotaKey, scope string, limit *user.APILimit, store storage.Handler, hashKeys bool) bool {
	logger := log.WithFields(logrus.Fields{
		"quotaMax":         limit.QuotaMax,
		"quotaRenewalRate": limit.QuotaRenewalRate,
	})

	if limit.QuotaMax <= 0 {
		return false
	}

	// don't use the requests cancellation context
	ctx := context.Background()

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

	now := time.Now()

	// rawKey is the redis key for quota
	rawKey := QuotaKeyPrefix + quotaScope + key

	var quotaRenewalRate time.Duration
	if limit.QuotaRenewalRate > 0 {
		quotaRenewalRate = time.Second * time.Duration(limit.QuotaRenewalRate)
	}

	conn := l.limiterStorage

	var expired, exists bool
	var expiredAt time.Time

	dur, err := conn.PTTL(ctx, rawKey).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		logger.WithError(err).Error("error getting key TTL, blocking")
		return true
	}

	// The command returns -2 if the key does not exist.
	// The command returns -1 if the key exists but has no associated expire.
	expired = dur < 0
	exists = dur != -2

	expiredAt = now.Add(dur)

	logger = logger.WithFields(logrus.Fields{
		"exists":  exists,
		"expired": expired,
		"rawKey":  rawKey,
	})

	increment := func() bool {
		var res *redis.IntCmd
		_, err := conn.Pipelined(ctx, func(pipe redis.Pipeliner) error {
			res = pipe.Incr(ctx, rawKey)
			if res.Val() == 1 && quotaRenewalRate > 0 {
				pipe.Expire(ctx, rawKey, quotaRenewalRate)
			}
			return nil
		})
		if err != nil {
			logger.WithError(err).Error("error incrementing quota key")
			return true
		}

		quota := res.Val()
		blocked := quota-1 >= limit.QuotaMax
		remaining := limit.QuotaMax - quota
		if blocked {
			remaining = 0
		}

		logger = logger.WithField("quota", quota-1)
		logger = logger.WithField("blocked", blocked)
		logger = logger.WithField("remaining", remaining)
		logger.Debug("[QUOTA] Update quota key")

		l.updateSessionQuota(session, scope, remaining, expiredAt.Unix())
		return blocked
	}

	// If exists and not expired, just increment it.
	if exists && !expired {
		return increment()
	}

	// if key is expired and can't renew, update the counter and
	// block traffic going forward.
	if limit.QuotaRenewalRate <= 0 {
		return increment()
	}

	// First, ensure a distributed lock
	locker := limiter.NewLimiter(conn).Locker(rawKey)

	// Lock the key
	if err := locker.Lock(ctx); err != nil {
		// Increment the key if lock fails
		return increment()
	}

	// Unlock the key when done
	defer func() {
		if err := locker.Unlock(ctx); err != nil {
			logger.WithError(err).Error("error unlocking quota key")
		}
	}()

	// locked: reset quota + increment
	conn.Set(ctx, rawKey, 0, quotaRenewalRate)
	return increment()
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

// updateSessionQuota updates session attached access rights.
//
// When limits are defined, QuotaRemaining and QuotaRenews is updated for a matching
// access rights definition for an api, and the session root.
func (*SessionLimiter) updateSessionQuota(session *user.SessionState, scope string, remaining int64, renews int64) {
	if remaining < 0 {
		remaining = 0
	}

	for k, v := range session.AccessRights {
		if v.Limit.IsEmpty() {
			continue
		}

		if v.AllowanceScope == scope {
			v.Limit.QuotaRemaining = remaining
			v.Limit.QuotaRenews = renews
		}
		session.AccessRights[k] = v
	}

	if scope == "" {
		session.QuotaRemaining = remaining
		session.QuotaRenews = renews
	}

	session.Touch()
}
