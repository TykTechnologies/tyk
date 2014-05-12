package main

import (
	"encoding/json"
	"fmt"
	"time"
)

// SessionState objects represent a current API session, mainly used for rate limiting.
type SessionState struct {
	LastCheck        int64   `json:"last_check"`
	Allowance        float64 `json:"allowance"`
	Rate             float64 `json:"rate"`
	Per              float64 `json:"per"`
	Expires          int64   `json:"expires"`
	QuotaMax         int64   `json:"quota_max"`
	QuotaRenews      int64   `json:"quota_renews"`
	QuotaRemaining   int64   `json:"quota_remaining"`
	QuotaRenewalRate int64   `json:"quota_renewal_rate"`
}

// SessionLimiter is the rate limiter for the API, use ForwardMessage() to
// check if a message should pass through or not
type SessionLimiter struct{}

// ForwardMessage will enforce rate limiting, returning false if session limits have been exceeded.
// Key values to manage rate are Rate and Per, e.g. Rate of 10 messages Per 10 seconds
func (l SessionLimiter) ForwardMessage(currentSession *SessionState) (bool, int) {

	current := time.Now().Unix()

	timePassed := current - currentSession.LastCheck
	currentSession.LastCheck = current
	currentSession.Allowance += float64(timePassed) * (currentSession.Rate / currentSession.Per)

	if currentSession.Allowance > currentSession.Rate {
		// Throttle
		currentSession.Allowance = currentSession.Rate
	}

	if currentSession.Allowance < 1.0 {
		return false, 1
	} else {
		currentSession.Allowance -= 1
		if !l.IsQuotaExceeded(currentSession) {
			return true, 0
		} else {
			return false, 2
		}

	}

}

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
		} else {
			// quota used up
			return true
		}
	}

	if currentSession.QuotaRemaining > 0 {
		currentSession.QuotaRemaining -= 1
		return false
	}

	return true

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

	b, _ := json.Marshal(thisSession)

	fmt.Println(string(b))
	return thisSession
}
