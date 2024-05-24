package apidef

import (
	"errors"
	"fmt"
	"time"
)

// RateLimitSmoothing holds the rate smoothing configuration in effect.
type RateLimitSmoothing struct {
	// Enabled if true will enable rate limit smoothing.
	Enabled bool `json:"enabled" bson:"enabled"`

	// Threshold is the request rate (measured over the rate limiter's `per` interval) above which gateway will apply smoothing. This must be lower than the configured `rate`, which indicates the absolute maximum request rate.
	Threshold int64 `json:"threshold" bson:"threshold"`

	// Trigger holds a value between 0..1 and is used to determine at which request rate smoothing will be triggered. 
	// A RateLimitSmoothingUp event will be triggered when the request rate reaches (step * trigger) below the current allowance.
	// A RateLimitSmoothingDown event will be triggered when the request rate is consistently below (step + (step * trigger)) below the current allowance.
	//
	// Example:
	//
	// - Allowance 600,
	// - Current rate 500,
	// - Step 100,
	// - Trigger 0.5
	//
	// To trigger a RateLimitSmoothingUp event, the current rate needs to exceed 550 requests per second.
	// The new allowance would be: `Allowance + Step`, i.e. 700.
	//
	// To trigger a RateLimitSmoothingDown event, the current rate needs to fall below 450.
	// The new allowance would be: `Allowance - Step`, i.e. 500.
	Trigger float64 `json:"trigger" bson:"trigger"`

	// Step defines the amount by which the currently enforced rate limit will be adjusted for a rate smoothing increase or decrease event.
	Step int64 `json:"step" bson:"step"`

	// Delay is the minimum period between changes to the currently enforced rate limit. This provides a hold-off to manage the smoothing of request spikes. It is a value in seconds.
	Delay int64 `json:"delay" bson:"delay"`

	// Allowance is the current allowance in effect. It's not
	// serialized for the database (bson), but has JSON tags
	// in order to store and return it with session data.
	Allowance int64 `json:"allowance_current" bson:"-"`

	// AllowanceNextUpdateAt is the time when Allowance is again allowed to update.
	// It's updated in SetAllowance.
	AllowanceNextUpdateAt time.Time `json:"allowance_next_update_at" bson:"-"`
}

// Valid will return true if the rate limit smoothing should be applied.
func (r *RateLimitSmoothing) Valid() bool {
	if err := r.Err(); err != nil {
		return false
	}
	return true
}

// Err checks the rate limit smoothing configuration for validity and returns an error if it is not valid.
// It checks for a nil value, the enabled flag, and valid values for each setting.
func (r *RateLimitSmoothing) Err() error {
	if r == nil || !r.Enabled {
		return errors.New("Rate limit smoothing disabled")
	}

	if r.Step <= 0 {
		return fmt.Errorf("Rate limit smoothing disabled: step invalid")
	}
	if r.Delay <= 0 {
		return fmt.Errorf("Rate limit smoothing disabled: delay invalid")
	}
	if r.Threshold <= 0 {
		return fmt.Errorf("Rate limit smoothing disabled: threshold invalid")
	}
	if r.Trigger <= 0 {
		return fmt.Errorf("Rate limit smoothing disabled: trigger invalid")
	}

	return nil
}

// GetDelay returns the delay for rate limit smoothing as a time.Duration.
func (r *RateLimitSmoothing) GetDelay() time.Duration {
	return time.Second * time.Duration(r.Delay)
}

// SetAllowance updates the current allowance to the specified value and
// sets the next update time based on the configured delay.
func (r *RateLimitSmoothing) SetAllowance(allowance int64) {
	r.Allowance = allowance
	r.Touch()
}

// Touch updates the next allowance time to the configured delay.
func (r *RateLimitSmoothing) Touch() {
	r.AllowanceNextUpdateAt = time.Now().Add(r.GetDelay())
}

// CanSetAllowance checks if the allowance can be updated based on the configured delay.
func (r *RateLimitSmoothing) CanSetAllowance() bool {
	return time.Since(r.AllowanceNextUpdateAt) > 0
}
