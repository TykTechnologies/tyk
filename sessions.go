package main

import (
	"encoding/json"
	"fmt"
	"time"
)

// SessionState objects represent a current API session, mainly used for rate limiting.
type SessionState struct {
	LastCheck int64   `json:"last_check"`
	Allowance float64 `json:"allowance"`
	Rate      float64 `json:"rate"`
	Per       float64 `json:"per"`
	Expires   int64 `json:"expires"`
}

// SessionLimiter is the rate limiter for the API, use ForwardMessage() to
// check if a message should pass through or not
type SessionLimiter struct{}

// ForwardMessage will enforce rate limiting, returning false if session limits have been exceeded.
// Key values to manage rate are Rate and Per, e.g. Rate of 10 messages Per 10 seconds
func (l SessionLimiter) ForwardMessage(currentSession *SessionState) bool {
	current := time.Now().Unix()

	timePassed := current - currentSession.LastCheck
	currentSession.LastCheck = current
	currentSession.Allowance += float64(timePassed) * (currentSession.Rate / currentSession.Per)

	if currentSession.Allowance > currentSession.Rate {
		// Throttle
		currentSession.Allowance = currentSession.Rate
	}

	if currentSession.Allowance < 1.0 {
		return false
	} else {
		currentSession.Allowance -= 1
		return true
	}
}

// createSampleSession is a debug function to create a mock session value
func createSampleSession() {
	var thisSession SessionState
	thisSession.Rate = 5.0
	thisSession.Allowance = thisSession.Rate
	thisSession.LastCheck = time.Now().Unix()
	thisSession.Per = 8.0
	thisSession.Expires = 0

	b, _ := json.Marshal(thisSession)

	fmt.Println(string(b))
}
