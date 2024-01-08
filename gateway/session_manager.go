package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-redsync/redsync/v4/redis/goredis/v9"
	"github.com/redis/go-redis/v9"

	"github.com/TykTechnologies/leakybucket"
	"github.com/TykTechnologies/leakybucket/memorycache"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/rate"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"

	"github.com/TykTechnologies/exp/pkg/limiters"
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
	Gw          *Gateway `json:"-"`

	redis redis.UniversalClient

	localLock limiters.DistLocker
	logger    limiters.Logger
	clock     limiters.Clock
}

// NewSessionLimiter initializes the session limiter.
//
// The session limiter initializes the storage required for rate limiters.
// It supports two storage types: `redis` and `local`. If redis storage is
// configured, then redis will be used. If local storage is configured, then
// in-memory counters will be used. If no storage is configured, it falls
// back onto the default gateway storage configuration.
func NewSessionLimiter(gateway *Gateway) SessionLimiter {
	sessionLimiter := SessionLimiter{
		Gw:          gateway,
		localLock:   limiters.NewLockNoop(),
		logger:      limiters.NewStdLogger(),
		clock:       limiters.NewSystemClock(),
		bucketStore: memorycache.New(),
	}

	cfg := gateway.GetConfig()

	// Use default storage if rate limiter storage is unconfigured.
	storageConf := &cfg.Storage
	if cfg.RateLimit.Storage != nil {
		storageConf = cfg.RateLimit.Storage
	}

	switch storageConf.Type {
	case "redis":
		sessionLimiter.redis = sessionLimiter.newRedisClient(storageConf)
	}

	return sessionLimiter
}

// redisLock creates an instance of a redis lock with redsync.
func (l *SessionLimiter) redisLock() *limiters.LockRedis {
	return limiters.NewLockRedis(goredis.NewPool(l.redis), "distributed-lock")
}

// newRedisClient is a typed copy of storage.NewRedisClusterPool.
func (*SessionLimiter) newRedisClient(cfg *config.StorageOptionsConf) redis.UniversalClient {
	// poolSize applies per cluster node and not for the whole cluster.
	poolSize := 500
	if cfg.MaxActive > 0 {
		poolSize = cfg.MaxActive
	}

	timeout := 5 * time.Second

	if cfg.Timeout > 0 {
		timeout = time.Duration(cfg.Timeout) * time.Second
	}

	var tlsConfig *tls.Config

	if cfg.UseSSL {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: cfg.SSLInsecureSkipVerify,
		}
	}

	opts := &redis.UniversalOptions{
		Addrs:            cfg.HostAddrs(),
		MasterName:       cfg.MasterName,
		SentinelPassword: cfg.SentinelPassword,
		Username:         cfg.Username,
		Password:         cfg.Password,
		DB:               cfg.Database,
		DialTimeout:      timeout,
		ReadTimeout:      timeout,
		WriteTimeout:     timeout,
		//		IdleTimeout:      240 * timeout,
		PoolSize:  poolSize,
		TLSConfig: tlsConfig,
	}

	if opts.MasterName != "" {
		log.Info("--> [REDIS] Creating sentinel-backed failover client")
		return redis.NewFailoverClient(opts.Failover())
	}

	if cfg.EnableCluster {
		log.Info("--> [REDIS] Creating cluster client")
		return redis.NewClusterClient(opts.Cluster())
	}

	log.Info("--> [REDIS] Creating single-node client")
	return redis.NewClient(opts.Simple())
}

func (l *SessionLimiter) Context() context.Context {
	return l.Gw.ctx
}

func (l *SessionLimiter) doRollingWindowWrite(key, rateLimiterKey, rateLimiterSentinelKey string,
	currentSession *user.SessionState,
	store storage.Handler,
	globalConf *config.Config,
	apiLimit *user.APILimit, dryRun bool) bool {

	ctx := l.Context()

	var per, cost float64

	if apiLimit != nil { // respect limit on API level
		per = apiLimit.Per
		cost = apiLimit.Rate
	} else {
		per = currentSession.Per
		cost = currentSession.Rate
	}

	log.Debug("[RATELIMIT] Inbound raw key is: ", key)
	log.Debug("[RATELIMIT] Rate limiter key is: ", rateLimiterKey)
	pipeline := globalConf.EnableNonTransactionalRateLimiter

	ratelimit, err := rate.NewSlidingLog(store, pipeline)
	if err != nil {
		log.WithError(err).Error("error creating sliding log")
		return true
	}

	var ratePerPeriodNow int64
	if dryRun {
		ratePerPeriodNow, err = ratelimit.GetCount(ctx, time.Now(), rateLimiterKey, int64(per))
	} else {
		ratePerPeriodNow, err = ratelimit.SetCount(ctx, time.Now(), rateLimiterKey, int64(per))
	}

	if err != nil {
		log.WithError(err).Error("error writing sliding log")
	}

	// Subtract by 1 because of the delayed add in the window
	var subtractor int64 = 1
	if globalConf.EnableSentinelRateLimiter || globalConf.DRLEnableSentinelRateLimiter {
		// and another subtraction because of the preemptive limit
		subtractor = 2
	}

	// The test TestRateLimitForAPIAndRateLimitAndQuotaCheck
	// will only work with these two lines here
	if ratePerPeriodNow > int64(cost)-subtractor {
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
	sessionFailInternalServerError
)

func (l *SessionLimiter) limitSentinel(currentSession *user.SessionState, key string, rateScope string, store storage.Handler,
	globalConf *config.Config, apiLimit *user.APILimit, dryRun bool) bool {

	rateLimiterKey := RateLimitKeyPrefix + rateScope + currentSession.KeyHash()
	rateLimiterSentinelKey := RateLimitKeyPrefix + rateScope + currentSession.KeyHash() + ".BLOCKED"

	defer func() {
		go l.doRollingWindowWrite(key, rateLimiterKey, rateLimiterSentinelKey, currentSession, store, globalConf, apiLimit, dryRun)
	}()

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

	rateLimiterKey := RateLimitKeyPrefix + rateScope + currentSession.KeyHash()
	rateLimiterSentinelKey := RateLimitKeyPrefix + rateScope + currentSession.KeyHash() + ".BLOCKED"

	if l.doRollingWindowWrite(key, rateLimiterKey, rateLimiterSentinelKey, currentSession, store, globalConf, apiLimit, dryRun) {
		return true
	}
	return false
}

func (l *SessionLimiter) limitDRL(currentSession *user.SessionState, key string, rateScope string,
	apiLimit *user.APILimit, dryRun bool) bool {

	bucketKey := key + ":" + rateScope + currentSession.LastUpdated
	currRate := apiLimit.Rate
	per := apiLimit.Per

	tokenValue := uint(l.Gw.DRLManager.CurrentTokenValue())

	// DRL will always overflow with more servers on low rates
	rate := uint(currRate * float64(l.Gw.DRLManager.RequestTokenValue))
	if rate < tokenValue {
		rate = tokenValue
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
func (l *SessionLimiter) ForwardMessage(r *http.Request, currentSession *user.SessionState, key string, store storage.Handler, enableRL, enableQ bool, globalConf *config.Config, api *APISpec, dryRun bool) sessionFailReason {
	// check for limit on API level (set to session by ApplyPolicies)
	accessDef, allowanceScope, err := GetAccessDefinitionByAPIIDOrSession(currentSession, api)
	if err != nil {
		log.WithField("apiID", api.APIID).Debugf("[RATE] %s", err.Error())
		return sessionFailRateLimit
	}

	if l.Gw == nil {
		panic("gateway not set in session limiter")
	}

	prefix := func(prefix, key, scope string) string {
		if scope != "" {
			return prefix + "-" + key + "-" + scope
		}
		return prefix + "-" + key
	}

	// If rate is -1 or 0, it means unlimited and no need for rate limiting.
	if enableRL && accessDef.Limit.Rate > 0 {
		rateScope := ""
		if allowanceScope != "" {
			rateScope = allowanceScope + "-"
		}

		switch {
		case globalConf.RateLimit.EnableLeakyBucket:
			var (
				storage limiters.LeakyBucketStateBackend
				locker  limiters.DistLocker
			)

			var (
				rate = int64(accessDef.Limit.Rate)
				per  = accessDef.Limit.Per
				ttl  = time.Duration(per) * time.Second

				outputRate = ttl / time.Duration(rate)

				raceCheck = false
			)

			rateLimitPrefix := prefix("leaky-bucket", key, allowanceScope)

			if l.redis != nil {
				locker = l.redisLock()
				storage = limiters.NewLeakyBucketRedis(l.redis, rateLimitPrefix, ttl, raceCheck)
			} else {
				locker = l.localLock
				storage = limiters.LocalLeakyBucket(rateLimitPrefix)
			}

			limiter := limiters.NewLeakyBucket(rate, outputRate, locker, storage, l.clock, l.logger)

			// Rate limiter returns a duration for how long to queue the request, or ErrLimitExhausted.
			res, err := limiter.Limit(r.Context())
			if errors.Is(err, limiters.ErrLimitExhausted) {
				return sessionFailRateLimit
			}
			time.Sleep(res)

		case globalConf.RateLimit.EnableTokenBucket:
			var (
				storage limiters.TokenBucketStateBackend
				locker  limiters.DistLocker
			)

			var (
				rate      = int64(accessDef.Limit.Rate)
				per       = accessDef.Limit.Per
				ttl       = time.Duration(per) * time.Second
				raceCheck = false
			)

			rateLimitPrefix := prefix("token-bucket", key, allowanceScope)

			if l.redis != nil {
				locker = l.redisLock()
				storage = limiters.NewTokenBucketRedis(l.redis, rateLimitPrefix, ttl, raceCheck)
			} else {
				locker = l.localLock
				storage = limiters.LocalTokenBucket(rateLimitPrefix)
			}

			limiter := limiters.NewTokenBucket(rate, ttl, locker, storage, l.clock, l.logger)

			// Rate limiter returns a zero duration and a possible ErrLimitExhausted when no tokens are available.
			_, err := limiter.Limit(r.Context())
			if errors.Is(err, limiters.ErrLimitExhausted) {
				return sessionFailRateLimit
			}

		case globalConf.RateLimit.EnableFixedWindow:
			var (
				storage limiters.FixedWindowIncrementer
			)

			var (
				rate = int64(accessDef.Limit.Rate)
				per  = accessDef.Limit.Per
				ttl  = time.Duration(per) * time.Second
			)

			rateLimitPrefix := prefix("fixed-window", key, allowanceScope)

			if l.redis != nil {
				storage = limiters.NewFixedWindowRedis(l.redis, rateLimitPrefix)
			} else {
				storage = limiters.LocalFixedWindow(rateLimitPrefix)
			}

			limiter := limiters.NewFixedWindow(rate, ttl, storage, l.clock)

			// Rate limiter returns a zero duration and a possible ErrLimitExhausted when no tokens are available.
			_, err := limiter.Limit(r.Context())
			if errors.Is(err, limiters.ErrLimitExhausted) {
				return sessionFailRateLimit
			}

		case globalConf.RateLimit.EnableSlidingWindow:
			var (
				storage limiters.SlidingWindowIncrementer
			)

			var (
				rate = int64(accessDef.Limit.Rate)
				per  = accessDef.Limit.Per
				ttl  = time.Duration(per) * time.Second
			)

			rateLimitPrefix := prefix("sliding-window", key, allowanceScope)

			if l.redis != nil {
				storage = limiters.NewSlidingWindowRedis(l.redis, rateLimitPrefix)
			} else {
				storage = limiters.LocalSlidingWindow(rateLimitPrefix)
			}

			// TODO: when doing rate sliding rate limits, the counts for two windows are
			//       used, the full count of the current window, and based on % of window
			//       time that has elapsed, a reduced previous window count.
			//
			//       the epsilon value is used to allow some requests to go over the defined
			//       rate limit at any point of the calculation (start of window, end of ...).
			limiter := limiters.NewSlidingWindow(rate, ttl, storage, l.clock, 0)

			// Rate limiter returns a zero duration and a possible ErrLimitExhausted when no tokens are available.
			_, err := limiter.Limit(r.Context())
			if errors.Is(err, limiters.ErrLimitExhausted) {
				return sessionFailRateLimit
			}

		case globalConf.EnableSentinelRateLimiter:
			if l.limitSentinel(currentSession, key, rateScope, store, globalConf, &accessDef.Limit, dryRun) {
				return sessionFailRateLimit
			}
		case globalConf.EnableRedisRollingLimiter:
			if l.limitRedis(currentSession, key, rateScope, store, globalConf, &accessDef.Limit, dryRun) {
				return sessionFailRateLimit
			}
		default:
			var n float64
			if l.Gw.DRLManager.Servers != nil {
				n = float64(l.Gw.DRLManager.Servers.Count())
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
				if l.limitDRL(currentSession, key, rateScope, &accessDef.Limit, dryRun) {
					return sessionFailRateLimit
				}
			} else {
				if l.limitRedis(currentSession, key, rateScope, store, globalConf, &accessDef.Limit, dryRun) {
					return sessionFailRateLimit
				}
			}
		}
	}

	if enableQ {
		if globalConf.LegacyEnableAllowanceCountdown {
			currentSession.Allowance = currentSession.Allowance - 1
		}

		if l.RedisQuotaExceeded(r, currentSession, allowanceScope, &accessDef.Limit, store, globalConf.HashKeys) {
			return sessionFailQuota
		}
	}

	return sessionFailNone

}

func (l *SessionLimiter) RedisQuotaExceeded(r *http.Request, currentSession *user.SessionState, scope string, limit *user.APILimit, store storage.Handler, hashKeys bool) bool {
	// Unlimited?
	if limit.QuotaMax == -1 || limit.QuotaMax == 0 {
		// No quota set
		return false
	}

	quotaScope := ""
	if scope != "" {
		quotaScope = scope + "-"
	}

	key := currentSession.KeyID

	if hashKeys {
		key = storage.HashStr(currentSession.KeyID)
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

	for k, v := range currentSession.AccessRights {
		if v.Limit.IsEmpty() {
			continue
		}

		if v.AllowanceScope == scope {
			v.Limit.QuotaRemaining = remaining
			v.Limit.QuotaRenews = quotaRenews
		}
		currentSession.AccessRights[k] = v
	}

	if scope == "" {
		currentSession.QuotaRemaining = remaining
		currentSession.QuotaRenews = quotaRenews
	}

	return false
}

func GetAccessDefinitionByAPIIDOrSession(currentSession *user.SessionState, api *APISpec) (accessDef *user.AccessDefinition, allowanceScope string, err error) {
	accessDef = &user.AccessDefinition{}
	if len(currentSession.AccessRights) > 0 {
		if rights, ok := currentSession.AccessRights[api.APIID]; !ok {
			return nil, "", errors.New("unexpected apiID")
		} else {
			accessDef.Limit = rights.Limit
			accessDef.FieldAccessRights = rights.FieldAccessRights
			accessDef.RestrictedTypes = rights.RestrictedTypes
			accessDef.AllowedTypes = rights.AllowedTypes
			accessDef.DisableIntrospection = rights.DisableIntrospection
			allowanceScope = rights.AllowanceScope
		}
	}
	if accessDef.Limit.IsEmpty() {
		accessDef.Limit = user.APILimit{
			QuotaMax:           currentSession.QuotaMax,
			QuotaRenewalRate:   currentSession.QuotaRenewalRate,
			QuotaRenews:        currentSession.QuotaRenews,
			Rate:               currentSession.Rate,
			Per:                currentSession.Per,
			ThrottleInterval:   currentSession.ThrottleInterval,
			ThrottleRetryLimit: currentSession.ThrottleRetryLimit,
			MaxQueryDepth:      currentSession.MaxQueryDepth,
		}
	}

	return accessDef, allowanceScope, nil
}
