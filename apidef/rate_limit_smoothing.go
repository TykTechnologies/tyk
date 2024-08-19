package apidef

import (
	"errors"
	"fmt"
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
// Events are emitted based on the configuration:
//
// - `enabled` (boolean) to enable or disable rate limit smoothing
// - `threshold` after which to apply smoothing (minimum rate for window)
// - `trigger` configures at which fraction of a step a smoothing event is emitted
// - `step` is the value by which the rate allowance will get adjusted
// - `delay` is a hold-off in seconds providing a minimum period between rate allowance adjustments
//
// To determine if the request rate is growing and needs to be smoothed, the
// `step * trigger` value is subtracted from the request allowance and, if
// the request rate goes above that, then a RateLimitSmoothingUp event is
// emitted and the rate allowance is increased by `step`.
//
// Once the request allowance has been increased above the `threshold`, Tyk
// will start to check for decreasing request rate. When the request rate
// drops `step * (1 + trigger)` below the request  allowance, a
// `RateLimitSmoothingDown` event is emitted and the rate allowance is
// decreased by `step`.
//
// After the request allowance has been adjusted (up or down), the request
// rate will be checked again over the next `delay` seconds and,  if
// required, further adjustment made to the rate allowance after the
// hold-off.
//
// For any allowance, events are emitted based on the following calculations:
//
//   - When the request rate rises above `allowance - (step * trigger)`,
//     a RateLimitSmoothingUp event is emitted and allowance increases by `step`.
//   - When the request rate falls below `allowance - (step + step * trigger)`,
//     a RateLimitSmoothingDown event is emitted and allowance decreases by `step`.
//
// Example: Threshold: 400, Request allowance: 600, Current rate: 500, Step: 100, Trigger: 0.5.
//
// To trigger a RateLimitSmoothingUp event, the request rate must exceed:
//
//   - Calculation: Allowance - (Step * Trigger).
//   - Example: 600 - (100 * 0.5) = `550`.
//
// Exceeding a request rate of `550` will increase the allowance to 700 (Allowance + Step).
//
// To trigger a RateLimitSmoothingDown event, the request rate must fall below:
//
//   - Calculation: Allowance - (Step + (Step * Trigger)).
//   - Example: 600 - (100 + (100 * 0.5)) = 450.
//
// As the request rate falls below 450, that will decrease the allowance to 500 (Allowance - Step).
//
// The request allowance will be smoothed between `threshold`, and the
// defined `rate` limit (maximum). The request allowance will be updated
// internally every `delay` seconds.
type RateLimitSmoothing struct {
	// Enabled indicates if rate limit smoothing is active.
	Enabled bool `json:"enabled" bson:"enabled"`

	// Threshold is the initial rate limit beyond which smoothing will be applied. It is a count of requests during the `per` interval and should be less than the maximum configured `rate`.
	Threshold int64 `json:"threshold" bson:"threshold"`

	// Trigger is a fraction (typically in the range 0.1-1.0) of the step at which point a smoothing event will be emitted as the request rate approaches the current allowance.
	Trigger float64 `json:"trigger" bson:"trigger"`

	// Step is the increment by which the current allowance will be increased or decreased each time a smoothing event is emitted.
	Step int64 `json:"step" bson:"step"`

	// Delay is a hold-off between smoothing events and controls how frequently the current allowance will step up or down (in seconds).
	Delay int64 `json:"delay" bson:"delay"`
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
		return errors.New("rate limit smoothing disabled")
	}

	if r.Step <= 0 {
		return fmt.Errorf("rate limit smoothing disabled: step invalid")
	}
	if r.Delay <= 0 {
		return fmt.Errorf("rate limit smoothing disabled: delay invalid")
	}
	if r.Threshold <= 0 {
		return fmt.Errorf("rate limit smoothing disabled: threshold invalid")
	}
	if r.Trigger <= 0 {
		return fmt.Errorf("rate limit smoothing disabled: trigger invalid")
	}

	return nil
}
