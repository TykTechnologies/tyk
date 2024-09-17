package rate

import (
	"fmt"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/redis"
)

// Smoothing implements rate limiter smoothing.
type Smoothing struct {
	allowanceStore AllowanceRepository
}

// NewSmoothing will return a new instance of *Smoothing.
func NewSmoothing(redis redis.UniversalClient) *Smoothing {
	return &Smoothing{
		allowanceStore: NewAllowanceStore(redis),
	}
}

// String returns the String output from the allowance store.
func (d *Smoothing) String() string {
	return d.allowanceStore.String()
}

// Do processes the rate limit smoothing based on the provided session settings and current rate.
//
// Internally it will get the current allowance, and if the update is allowed will
// acquire a lock, re-read the allowance, evaluate a smoothing change and write an
// updated allowance to redis.
//
// An allowance may be returned together with an error. For example, if the distributed
// lock fails for some reason, the previous Get result that succeeded will be returned,
// alongside the error. If no error occured, the current allowance in effect is returned.
//
// If an error occured writing an allowance, the previous allowance will be returned.
func (d *Smoothing) Do(r *http.Request, session *apidef.RateLimitSmoothing, key string, currentRate int64, maxAllowedRate int64) (*Allowance, error) {
	// Rate limit smoothing is disabled or threshold is unset, no change, no error.
	if !session.Valid() {
		return nil, fmt.Errorf("smoothing invalid: %w", session.Err())
	}

	ctx := r.Context()

	var createAllowance bool

	allowance, err := d.allowanceStore.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("smoothing: getting allowance: %w", err)
	}

	if allowance.Delay == 0 {
		// Set new allowance if none exists in storage.
		// Starts with the Threshold (minimum allowance).
		allowance = NewAllowance(session.Delay)
		allowance.Current = session.Threshold
		createAllowance = true
	}

	// Allowance can only be set once per defined interval
	if !createAllowance && !allowance.Expired() {
		return allowance, nil
	}

	// Handle distributed lock for the write
	locker := d.allowanceStore.Locker(key)

	// Lock protects get/set from a data race
	if err := locker.Lock(ctx); err != nil {
		return allowance, fmt.Errorf("smoothing: getting lock, skipping update: %w", err)
	}
	defer func() {
		_ = locker.Unlock(ctx)
	}()

	// Create allowance
	if createAllowance {
		allowance.Touch()
		if err := d.allowanceStore.Set(ctx, key, allowance); err != nil {
			// return previous allowance and error
			return allowance, fmt.Errorf("smoothing: can't set new allowance: %w", err)
		}
		return allowance, nil
	}

	// Re-read allowance behind the lock to have accurate state
	allowance, err = d.allowanceStore.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("smoothing: getting allowance: %w", err)
	}

	// Allowance can only be set once per defined interval
	if !allowance.Expired() {
		return allowance, nil
	}

	// Get current allowed rate
	allowedRate := allowance.Get()

	// Increase allowance if necessary
	if newAllowedRate, changed := increaseRateAllowance(session, allowedRate, currentRate, maxAllowedRate); changed {
		newAllowance := NewAllowance(allowance.Delay)
		newAllowance.Set(newAllowedRate)

		if err := d.allowanceStore.Set(ctx, key, newAllowance); err != nil {
			// return previous allowance and error
			return allowance, fmt.Errorf("smoothing: can't set allowance increase: %w", err)
		}

		event.Add(r, event.RateLimitSmoothingUp)
		return newAllowance, nil
	}

	// Decrease allowance if necessary
	if newAllowedRate, changed := decreaseRateAllowance(session, allowedRate, currentRate, session.Threshold); changed {
		newAllowance := NewAllowance(allowance.Delay)
		newAllowance.Set(newAllowedRate)

		if err := d.allowanceStore.Set(ctx, key, newAllowance); err != nil {
			// return previous allowance and error
			return allowance, fmt.Errorf("smoothing: can't set allowance decrease: %w", err)
		}

		event.Add(r, event.RateLimitSmoothingDown)
		return newAllowance, nil
	}

	// return previous allowance (no smoothing performed)
	return allowance, nil
}

func increaseRateAllowance(session *apidef.RateLimitSmoothing, allowedRate int64, currentRate int64, maxAllowedRate int64) (int64, bool) {
	step := float64(allowedRate) - session.Trigger*float64(session.Step)
	newAllowedRate := allowedRate + session.Step
	if float64(currentRate) >= step {
		// clamp to the max rate
		if newAllowedRate > maxAllowedRate {
			newAllowedRate = maxAllowedRate
		}
		return newAllowedRate, newAllowedRate != allowedRate
	}
	return allowedRate, false
}

func decreaseRateAllowance(session *apidef.RateLimitSmoothing, allowedRate int64, currentRate int64, minAllowedRate int64) (int64, bool) {
	newAllowedRate := allowedRate - session.Step
	step := float64(newAllowedRate) - session.Trigger*float64(session.Step)
	if float64(currentRate) <= step {
		if newAllowedRate < minAllowedRate {
			newAllowedRate = minAllowedRate
		}
		return newAllowedRate, newAllowedRate != allowedRate
	}
	return allowedRate, false
}
