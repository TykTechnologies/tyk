package apidef

import (
	"errors"
	"fmt"
	"time"
)

// RateLimitSmoothing holds the rate smoothing configuration.
//
// Rate Limit Smoothing is a mechanism to dynamically adjust the request rate
// limits based on the current traffic patterns. It helps in managing request
// spikes by gradually increasing or decreasing the rate limit instead of making
// abrupt changes or blocking requests excessively.
//
// Once the rate limit smoothing triggers an allowance change, one of the
// following events is emitted:
//
// - `RateLimitSmoothingUp` when the allowance increases
// - `RateLimitSmoothingDown` when the allowance decreases
//
// Events are triggered based on the configuration:
//
// - `enabled` (boolean) to enable or disable rate limit smoothing
// - `threshold` after which to apply smoothing (minimum rate for window)
// - `trigger` configures at which fraction of a step a smoothing event is triggered
// - `step` is the value by which the rate allowance will get adjusted
// - `delay` is the amount of seconds between smoothing updates
//
// This configuration in turn updates two fields:
//
// - `allowance` - the current rate allowance enforced when rate limiting
// - `allowance_next_update_at` - a timestamp when the next allowance update may occur
//
// For any allowance, events are triggered based on the following calculations:
//
//   - When the request rate rises above `allowance - (step * trigger)`,
//     a RateLimitSmoothingUp event is emitted and allowance increases by `step`.
//   - When the request rate falls below `allowance - (step + step * trigger)`,
//     a RateLimitSmoothingDown event is emitted and allowance decreases by `step`.
//
// Example: Allowance: 600, Current rate: 500, Step: 100, Trigger: 0.5
//
//   - To trigger a RateLimitSmoothingUp event, the request rate must exceed:
//     Allowance - (Step * Trigger)
//     Calculation: 600 - (100 * 0.5) = 550
//     Exceeding a request rate of 550 will increase the allowance to 700 (Allowance + Step).
//
//   - To trigger a RateLimitSmoothingDown event, the request rate must fall below:
//     Allowance - (Step + (Step * Trigger))
//     Calculation: 600 - (100 + (100 * 0.5)) = 450
//     As the request rate falls below 450, that will decrease the allowance to 500 (Allowance - Step).
type RateLimitSmoothing struct {
	// Enabled indicates if rate limit smoothing is active.
	Enabled bool `json:"enabled" bson:"enabled"`

	// Threshold is the request rate above which smoothing is applied.
	Threshold int64 `json:"threshold" bson:"threshold"`

	// Trigger is the step factor (0..1) determining when smoothing events trigger.
	Trigger float64 `json:"trigger" bson:"trigger"`

	// Step is the increment/decrement for adjusting the rate limit.
	Step int64 `json:"step" bson:"step"`

	// Delay is the minimum time between rate limit changes (in seconds).
	Delay int64 `json:"delay" bson:"delay"`

	// Allowance is the current rate limit allowance in effect.
	Allowance int64 `json:"allowance" bson:"-"`

	// AllowanceNextUpdateAt is the next allowable update time for the allowance.
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
// It checks for a nil value, the enabled flag and valid values for each setting.
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
