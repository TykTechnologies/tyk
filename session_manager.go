package main

import (
	"time"

	"github.com/TykTechnologies/leakybucket"
	"github.com/TykTechnologies/leakybucket/memorycache"
	"github.com/TykTechnologies/tyk/config"
)

type PublicSessionState struct {
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

func (l *SessionLimiter) doRollingWindowWrite(key, rateLimiterKey, rateLimiterSentinelKey string, currentSession *SessionState, store StorageHandler) bool {
	log.Debug("[RATELIMIT] Inbound raw key is: ", key)
	log.Debug("[RATELIMIT] Rate limiter key is: ", rateLimiterKey)
	var ratePerPeriodNow int
	if config.Global.EnableNonTransactionalRateLimiter {
		ratePerPeriodNow, _ = store.SetRollingWindowPipeline(rateLimiterKey, int64(currentSession.Per), "-1")
	} else {
		ratePerPeriodNow, _ = store.SetRollingWindow(rateLimiterKey, int64(currentSession.Per), "-1")
	}

	//log.Info("Num Requests: ", ratePerPeriodNow)

	// Subtract by 1 because of the delayed add in the window
	subtractor := 1
	if config.Global.EnableSentinelRateLImiter {
		// and another subtraction because of the preemptive limit
		subtractor = 2
	}

	//log.Info("break: ", (int(currentSession.Rate) - subtractor))

	if ratePerPeriodNow > int(currentSession.Rate)-subtractor {
		// Set a sentinel value with expire
		if config.Global.EnableSentinelRateLImiter {
			store.SetRawKey(rateLimiterSentinelKey, "1", int64(currentSession.Per))
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
)

// ForwardMessage will enforce rate limiting, returning a non-zero
// sessionFailReason if session limits have been exceeded.
// Key values to manage rate are Rate and Per, e.g. Rate of 10 messages
// Per 10 seconds
func (l *SessionLimiter) ForwardMessage(currentSession *SessionState, key string, store StorageHandler, enableRL, enableQ bool) sessionFailReason {
	rateLimiterKey := RateLimitKeyPrefix + hashKey(key)
	rateLimiterSentinelKey := RateLimitKeyPrefix + hashKey(key) + ".BLOCKED"

	if enableRL {
		if config.Global.EnableSentinelRateLImiter {
			go l.doRollingWindowWrite(key, rateLimiterKey, rateLimiterSentinelKey, currentSession, store)

			// Check sentinel
			_, sentinelActive := store.GetRawKey(rateLimiterSentinelKey)
			if sentinelActive == nil {
				// Sentinel is set, fail
				return sessionFailRateLimit
			}
		} else if config.Global.EnableRedisRollingLimiter {
			if l.doRollingWindowWrite(key, rateLimiterKey, rateLimiterSentinelKey, currentSession, store) {
				return sessionFailRateLimit
			}
		} else {
			// In-memory limiter
			if l.bucketStore == nil {
				l.bucketStore = memorycache.New()
			}

			// If a token has been updated, we must ensure we dont use
			// an old bucket an let the cache deal with it
			bucketKey := key + ":" + currentSession.LastUpdated

			// DRL will always overflow with more servers on low rates
			rate := uint(currentSession.Rate * float64(DRLManager.RequestTokenValue))
			if rate < uint(DRLManager.CurrentTokenValue) {
				rate = uint(DRLManager.CurrentTokenValue)
			}

			userBucket, err := l.bucketStore.Create(bucketKey,
				rate,
				time.Duration(currentSession.Per)*time.Second)
			if err != nil {
				log.Error("Failed to create bucket!")
				return sessionFailRateLimit
			}

			_, errF := userBucket.Add(uint(DRLManager.CurrentTokenValue))

			if errF != nil {
				return sessionFailRateLimit
			}
		}
	}

	if enableQ {
		if config.Global.LegacyEnableAllowanceCountdown {
			currentSession.Allowance--
		}

		if l.IsRedisQuotaExceeded(currentSession, key, store) {
			return sessionFailQuota
		}
	}

	return sessionFailNone

}

func (l *SessionLimiter) IsRedisQuotaExceeded(currentSession *SessionState, key string, store StorageHandler) bool {

	// Are they unlimited?
	if currentSession.QuotaMax == -1 {
		// No quota set
		return false
	}

	// Create the key
	log.Debug("[QUOTA] Inbound raw key is: ", key)
	rawKey := QuotaKeyPrefix + hashKey(key)
	log.Debug("[QUOTA] Quota limiter key is: ", rawKey)
	log.Debug("Renewing with TTL: ", currentSession.QuotaRenewalRate)
	// INCR the key (If it equals 1 - set EXPIRE)
	qInt := store.IncrememntWithExpire(rawKey, currentSession.QuotaRenewalRate)

	// if the returned val is >= quota: block
	if qInt-1 >= currentSession.QuotaMax {
		renewalDate := time.Unix(currentSession.QuotaRenews, 0)
		log.Debug("Renewal Date is: ", renewalDate)
		log.Debug("As epoch: ", currentSession.QuotaRenews)
		log.Debug("Session: ", currentSession)
		log.Debug("Now:", time.Now())
		if time.Now().After(renewalDate) {
			// The renewal date is in the past, we should update the quota!
			// Also, this fixes legacy issues where there is no TTL on quota buckets
			log.Warning("Incorrect key expiry setting detected, correcting")
			go store.DeleteRawKey(rawKey)
			qInt = 1
		} else {
			// Renewal date is in the future and the quota is exceeded
			return true
		}

	}

	// If this is a new Quota period, ensure we let the end user know
	if qInt == 1 {
		current := time.Now().Unix()
		currentSession.QuotaRenews = current + currentSession.QuotaRenewalRate
	}

	// If not, pass and set the values of the session to quotamax - counter
	remaining := currentSession.QuotaMax - qInt

	if remaining < 0 {
		currentSession.QuotaRemaining = 0
	} else {
		currentSession.QuotaRemaining = remaining
	}
	return false
}
