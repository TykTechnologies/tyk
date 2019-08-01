package main

import (
	"net/http"
	"time"

	"github.com/TykTechnologies/leakybucket"
	"github.com/TykTechnologies/leakybucket/memorycache"
	"github.com/TykTechnologies/tyk/config"
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
	if globalConf.EnableSentinelRateLimiter {
		// and another subtraction because of the preemptive limit
		subtractor = 2
	}
	// The test TestRateLimitForAPIAndRateLimitAndQuotaCheck
	// will only work with ththese two lines here
	//log.Info("break: ", (int(currentSession.Rate) - subtractor))
	if ratePerPeriodNow > int(rate)-subtractor {
		// Set a sentinel value with expire
		if globalConf.EnableSentinelRateLimiter {
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
)

// ForwardMessage will enforce rate limiting, returning a non-zero
// sessionFailReason if session limits have been exceeded.
// Key values to manage rate are Rate and Per, e.g. Rate of 10 messages
// Per 10 seconds
func (l *SessionLimiter) ForwardMessage(r *http.Request, currentSession *user.SessionState, key string, store storage.Handler, enableRL, enableQ bool, globalConf *config.Config, apiID string, dryRun bool) sessionFailReason {
	if enableRL {
		// check for limit on API level (set to session by ApplyPolicies)
		var apiLimit *user.APILimit
		if len(currentSession.AccessRights) > 0 {
			if rights, ok := currentSession.AccessRights[apiID]; !ok {
				log.WithField("apiID", apiID).Debug("[RATE] unexpected apiID")
				return sessionFailRateLimit
			} else {
				apiLimit = rights.Limit
			}
		}

		if globalConf.EnableSentinelRateLimiter {
			rateLimiterKey := RateLimitKeyPrefix + currentSession.KeyHash()
			rateLimiterSentinelKey := RateLimitKeyPrefix + currentSession.KeyHash() + ".BLOCKED"
			if apiLimit != nil {
				rateLimiterKey = RateLimitKeyPrefix + apiID + "-" + currentSession.KeyHash()
				rateLimiterSentinelKey = RateLimitKeyPrefix + apiID + "-" + currentSession.KeyHash() + ".BLOCKED"
			}

			go l.doRollingWindowWrite(key, rateLimiterKey, rateLimiterSentinelKey, currentSession, store, globalConf, apiLimit, dryRun)

			// Check sentinel
			_, sentinelActive := store.GetRawKey(rateLimiterSentinelKey)
			if sentinelActive == nil {
				// Sentinel is set, fail
				return sessionFailRateLimit
			}
		} else if globalConf.EnableRedisRollingLimiter {
			rateLimiterKey := RateLimitKeyPrefix + currentSession.KeyHash()
			rateLimiterSentinelKey := RateLimitKeyPrefix + currentSession.KeyHash() + ".BLOCKED"
			if apiLimit != nil {
				rateLimiterKey = RateLimitKeyPrefix + apiID + "-" + currentSession.KeyHash()
				rateLimiterSentinelKey = RateLimitKeyPrefix + apiID + "-" + currentSession.KeyHash() + ".BLOCKED"
			}

			if l.doRollingWindowWrite(key, rateLimiterKey, rateLimiterSentinelKey, currentSession, store, globalConf, apiLimit, dryRun) {
				return sessionFailRateLimit
			}
		} else {
			// In-memory limiter
			if l.bucketStore == nil {
				l.bucketStore = memorycache.New()
			}

			// If a token has been updated, we must ensure we don't use
			// an old bucket an let the cache deal with it
			bucketKey := ""
			var currRate float64
			var per float64
			if apiLimit == nil {
				bucketKey = key + ":" + currentSession.LastUpdated
				currRate = currentSession.Rate
				per = currentSession.Per
			} else { // respect limit on API level
				bucketKey = apiID + ":" + key + ":" + currentSession.LastUpdated
				currRate = apiLimit.Rate
				per = apiLimit.Per
			}

			// DRL will always overflow with more servers on low rates
			rate := uint(currRate * float64(DRLManager.RequestTokenValue))
			if rate < uint(DRLManager.CurrentTokenValue) {
				rate = uint(DRLManager.CurrentTokenValue)
			}

			userBucket, err := l.bucketStore.Create(bucketKey, rate, time.Duration(per)*time.Second)
			if err != nil {
				log.Error("Failed to create bucket!")
				return sessionFailRateLimit
			}

			if dryRun {
				// if userBucket is empty and not expired.
				if userBucket.Remaining() == 0 && time.Now().Before(userBucket.Reset()) {
					return sessionFailRateLimit
				}
			} else {
				_, errF := userBucket.Add(uint(DRLManager.CurrentTokenValue))
				if errF != nil {
					return sessionFailRateLimit
				}
			}
		}
	}

	if enableQ {
		if globalConf.LegacyEnableAllowanceCountdown {
			currentSession.Allowance--
		}

		if l.RedisQuotaExceeded(r, currentSession, key, store, apiID) {
			return sessionFailQuota
		}
	}

	return sessionFailNone

}

func (l *SessionLimiter) RedisQuotaExceeded(r *http.Request, currentSession *user.SessionState, key string, store storage.Handler, apiID string) bool {
	log.Debug("[QUOTA] Inbound raw key is: ", key)

	// check for limit on API level (set to session by ApplyPolicies)
	var apiLimit *user.APILimit
	if len(currentSession.AccessRights) > 0 {
		if rights, ok := currentSession.AccessRights[apiID]; !ok {
			log.WithField("apiID", apiID).Debug("[QUOTA] unexpected apiID")
			return false
		} else {
			apiLimit = rights.Limit
		}
	}

	// Are they unlimited?
	if apiLimit == nil {
		if currentSession.QuotaMax == -1 {
			// No quota set
			return false
		}
	} else if apiLimit.QuotaMax == -1 {
		// No quota set
		return false
	}

	rawKey := ""
	var quotaRenewalRate int64
	var quotaRenews int64
	var quotaMax int64
	if apiLimit == nil {
		rawKey = QuotaKeyPrefix + currentSession.KeyHash()
		quotaRenewalRate = currentSession.QuotaRenewalRate
		quotaRenews = currentSession.QuotaRenews
		quotaMax = currentSession.QuotaMax
	} else {
		rawKey = QuotaKeyPrefix + apiID + "-" + currentSession.KeyHash()
		quotaRenewalRate = apiLimit.QuotaRenewalRate
		quotaRenews = apiLimit.QuotaRenews
		quotaMax = apiLimit.QuotaMax
	}

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
		current := time.Now().Unix()
		if apiLimit == nil {
			currentSession.QuotaRenews = current + quotaRenewalRate
		} else {
			apiLimit.QuotaRenews = current + quotaRenewalRate
		}
		ctxScheduleSessionUpdate(r)
	}

	// If not, pass and set the values of the session to quotamax - counter
	remaining := quotaMax - qInt
	if remaining < 0 {
		remaining = 0
	}

	if apiLimit == nil {
		currentSession.QuotaRemaining = remaining
	} else {
		apiLimit.QuotaRemaining = remaining
	}

	return false
}
