package apidef

import (
	"errors"
	"fmt"
)

// RateLimitSmoothing holds the rate smoothing configuration in effect.
type RateLimitSmoothing struct {
	// Enabled if true will enable rate limit smoothing.
	Enabled bool `json:"enabled" bson:"enabled"`

	Rate      int64   `json:"rate" bson:"rate"`
	Interval  int64   `json:"interval" bson:"interval"`
	Threshold int64   `json:"threshold" bson:"treshold"`
	Trigger   float64 `json:"trigger" bson:"trigger"`

	// Allowance is the current allowance in effect. It's not
	// serialized for the database (bson), but has JSON tags
	// in order to store and return it with session data.
	Allowance int64 `json:"allowance" bson:"-"`
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
