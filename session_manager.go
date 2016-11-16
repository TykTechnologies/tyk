package main

import (
	"time"
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
	QuotaKeyPrefix     string = "quota-"
	RateLimitKeyPrefix string = "rate-limit-"
)

// SessionLimiter is the rate limiter for the API, use ForwardMessage() to
// check if a message should pass through or not
type SessionLimiter struct{}

func (l SessionLimiter) doRollingWindowWrite(key, rateLimiterKey, rateLimiterSentinelKey string, currentSession *SessionState, store StorageHandler) bool {
	log.Debug("[RATELIMIT] Inbound raw key is: ", key)
	log.Debug("[RATELIMIT] Rate limiter key is: ", rateLimiterKey)
	var ratePerPeriodNow int
	if config.EnableNonTransactionalRateLimiter {
		ratePerPeriodNow, _ = store.SetRollingWindowPipeline(rateLimiterKey, int64(currentSession.Per), "-1")
	} else {
		ratePerPeriodNow, _ = store.SetRollingWindow(rateLimiterKey, int64(currentSession.Per), "-1")
	}

	//log.Info("Num Requests: ", ratePerPeriodNow)

	// Subtract by 1 because of the delayed add in the window
	subtractor := 1
	if config.EnableSentinelRateLImiter {
		// and another subtraction because of the preemptive limit
		subtractor = 2
	}

	//log.Info("break: ", (int(currentSession.Rate) - subtractor))

	if ratePerPeriodNow > (int(currentSession.Rate) - subtractor) {
		// Set a sentinel value with expire
		if config.EnableSentinelRateLImiter {
			store.SetRawKey(rateLimiterSentinelKey, "1", int64(currentSession.Per))
		}
		return true
	}

	return false
}

// ForwardMessage will enforce rate limiting, returning false if session limits have been exceeded.
// Key values to manage rate are Rate and Per, e.g. Rate of 10 messages Per 10 seconds
func (l SessionLimiter) ForwardMessage(currentSession *SessionState, key string, store StorageHandler, enableRL, enableQ bool) (bool, int) {
	rateLimiterKey := RateLimitKeyPrefix + publicHash(key)
	rateLimiterSentinelKey := RateLimitKeyPrefix + publicHash(key) + ".BLOCKED"

	if enableRL {
		if config.EnableSentinelRateLImiter {
			go l.doRollingWindowWrite(key, rateLimiterKey, rateLimiterSentinelKey, currentSession, store)

			// Check sentinel
			_, sentinelActive := store.GetRawKey(rateLimiterSentinelKey)
			if sentinelActive == nil {
				// Sentinel is set, fail
				return false, 1
			}
		} else if config.EnableRedisRollingLimiter {
			if l.doRollingWindowWrite(key, rateLimiterKey, rateLimiterSentinelKey, currentSession, store) {
				return false, 1
			}
		} else {
			// In-memory limiter
			if BucketStore == nil {
				InitBucketStore()
			}

			// If a token has been updated, we must ensure we dont use
			// an old bucket an let the cache deal with it
			bucketKey := key + ":" + currentSession.LastUpdated

			// DRL will always overflow with more servers on low rates
			thisRate := uint(currentSession.Rate*float64(DRLManager.RequestTokenValue))
			if thisRate < uint(DRLManager.CurrentTokenValue) {
				thisRate = uint(DRLManager.CurrentTokenValue)
			}

			thisUserBucket, cErr := BucketStore.Create(bucketKey,
				thisRate,
				time.Duration(currentSession.Per)*time.Second)

			if cErr != nil {
				log.Error("Failed to create bucket!")
				return false, 1
			}

			//log.Info("Add is: ", DRLManager.CurrentTokenValue)
			_, errF := thisUserBucket.Add(uint(DRLManager.CurrentTokenValue))

			if errF != nil {
				return false, 1
			}
		}
	}

	if enableQ {
		if config.LegacyEnableAllowanceCountdown {
			currentSession.Allowance--	
		}
		
		if l.IsRedisQuotaExceeded(currentSession, key, store) {
			return false, 2
		}
	}

	return true, 0

}

// ForwardMessageNaiveKey is the old redis-key ttl-based Rate limit, it could be gamed.
func (l SessionLimiter) ForwardMessageNaiveKey(currentSession *SessionState, key string, store StorageHandler) (bool, int) {

	log.Debug("[RATELIMIT] Inbound raw key is: ", key)
	rateLimiterKey := RateLimitKeyPrefix + publicHash(key)
	log.Debug("[RATELIMIT] Rate limiter key is: ", rateLimiterKey)
	ratePerPeriodNow := store.IncrememntWithExpire(rateLimiterKey, int64(currentSession.Per))

	if ratePerPeriodNow > (int64(currentSession.Rate)) {
		return false, 1
	}

	currentSession.Allowance--
	if !l.IsRedisQuotaExceeded(currentSession, key, store) {
		return true, 0
	}

	return false, 2

}

// IsQuotaExceeded will confirm if a session key has exceeded it's quota, if a quota has been exceeded,
// but the quata renewal time has passed, it will be refreshed.
func (l SessionLimiter) IsQuotaExceeded(currentSession *SessionState) bool {
	if currentSession.QuotaMax == -1 {
		// No quota set
		return false
	}

	if currentSession.QuotaRemaining == 0 {
		current := time.Now().Unix()
		if currentSession.QuotaRenews-current < 0 {
			// quota used up, but we're passed renewal time
			currentSession.QuotaRenews = current + currentSession.QuotaRenewalRate
			currentSession.QuotaRemaining = currentSession.QuotaMax
			return false
		}
		// quota used up
		return true
	}

	if currentSession.QuotaRemaining > 0 {
		currentSession.QuotaRemaining--
		return false
	}

	return true

}

func (l SessionLimiter) IsRedisQuotaExceeded(currentSession *SessionState, key string, store StorageHandler) bool {

	// Are they unlimited?
	if currentSession.QuotaMax == -1 {
		// No quota set
		return false
	}

	// Create the key
	log.Debug("[QUOTA] Inbound raw key is: ", key)
	rawKey := QuotaKeyPrefix + publicHash(key)
	log.Debug("[QUOTA] Quota limiter key is: ", rawKey)
	log.Debug("Renewing with TTL: ", currentSession.QuotaRenewalRate)
	// INCR the key (If it equals 1 - set EXPIRE)
	qInt := store.IncrememntWithExpire(rawKey, currentSession.QuotaRenewalRate)

	// if the returned val is >= quota: block
	if (int64(qInt) - 1) >= currentSession.QuotaMax {
		RenewalDate := time.Unix(currentSession.QuotaRenews, 0)
		log.Debug("Renewal Date is: ", RenewalDate)
		log.Debug("As epoch: ", currentSession.QuotaRenews)
		log.Debug("Session: ", currentSession)
		log.Debug("Now:", time.Now())
		if time.Now().After(RenewalDate) {
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
	if int64(qInt) == 1 {
		current := time.Now().Unix()
		currentSession.QuotaRenews = current + currentSession.QuotaRenewalRate
	}

	// If not, pass and set the values of the session to quotamax - counter
	remaining := currentSession.QuotaMax - int64(qInt)

	if remaining < 0 {
		currentSession.QuotaRemaining = 0
	} else {
		currentSession.QuotaRemaining = remaining
	}
	return false
}

// createSampleSession is a debug function to create a mock session value
func createSampleSession() SessionState {
	var thisSession SessionState
	thisSession.Rate = 5.0
	thisSession.Allowance = thisSession.Rate
	thisSession.LastCheck = time.Now().Unix()
	thisSession.Per = 8.0
	thisSession.Expires = 0
	thisSession.QuotaRenewalRate = 300 // 5 minutes
	thisSession.QuotaRenews = time.Now().Unix()
	thisSession.QuotaRemaining = 10
	thisSession.QuotaMax = 10

	simpleDef := AccessDefinition{
		APIName:  "Test",
		APIID:    "1",
		Versions: []string{"Default"},
	}
	thisSession.AccessRights = map[string]AccessDefinition{}
	thisSession.AccessRights["1"] = simpleDef

	return thisSession
}
