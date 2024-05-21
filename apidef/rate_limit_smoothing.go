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

	// Rate defines the step amount for a rate smoothing increase or decrease.
	Rate int64 `json:"rate" bson:"rate"`

	// Interval holds the number of seconds between allowance updates.
	Interval int64 `json:"interval" bson:"interval"`

	// Treshold is the value above which gateway will apply smoothing.
	Threshold int64 `json:"threshold" bson:"threshold"`

	// Triger holds a value between 0..1 and is used as a percentage value of the
	// rate limit to reach, before triggering a SmoothingUp event. Similarly the
	// value is also used to decrease the allowance when rate limits decrease.
	Trigger float64 `json:"trigger" bson:"trigger"`

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

// Err will return an error if the rate limit smoothing configuration is not valid.
// It checks for a nil value, the enabled flag, and valid values for each setting.
func (r *RateLimitSmoothing) Err() error {
	if r == nil || !r.Enabled {
		return errors.New("Rate limit smoothing disabled")
	}

	if r.Rate <= 0 {
		return fmt.Errorf("Rate limit smoothing disabled: rate invalid")
	}
	if r.Interval <= 0 {
		return fmt.Errorf("Rate limit smoothing disabled: interval invalid")
	}
	if r.Threshold <= 0 {
		return fmt.Errorf("Rate limit smoothing disabled: threshold invalid")
	}
	if r.Trigger <= 0 {
		return fmt.Errorf("Rate limit smoothing disabled: trigger invalid")
	}

	return nil
}

// GetInterval returns a time.Duration of the configured interval value.
func (r *RateLimitSmoothing) GetInterval() time.Duration {
	return time.Second * time.Duration(r.Interval)
}

// SetAllowance will update the allowance and set a new timestamp for the next update.
func (r *RateLimitSmoothing) SetAllowance(allowance int64) {
	r.Allowance = allowance
	r.AllowanceNextUpdateAt = time.Now().Add(r.GetInterval())
}

// CanSetAllowance will return true if allowance can be updated based on the configured interval.
func (r *RateLimitSmoothing) CanSetAllowance() bool {
	return time.Since(r.AllowanceNextUpdateAt) > 0
}
