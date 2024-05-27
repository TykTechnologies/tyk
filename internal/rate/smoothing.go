package rate

import (
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/event"
)

// Smoothing processes the rate limit smoothing based on the provided session settings and current rate.
// The first returned value indicates if smoothing was performed. An optionally filled error
// returns any details as to why smoothing wasn't performed and should be used for logging purposes.
func Smoothing(r *http.Request, session *apidef.RateLimitSmoothing, key string, currentRate int64, maxAllowedRate int64) (bool, error) {
	// Rate limit smoothing is disabled or threshold is unset, no change, no error.
	if !session.Valid() {
		return false, nil
	}

	// Allowance can only be set once per defined interval
	if !session.CanSetAllowance() {
		return false, nil
	}

	// Increase allowance if necessary
	if newAllowance, changed := increaseRateAllowance(session, currentRate, maxAllowedRate); changed {
		event.Add(r, event.RateLimitSmoothingUp)
		session.SetAllowance(newAllowance)
		return true, nil
	}

	// Decrease allowance if necessary
	if newAllowance, changed := decreaseRateAllowance(session, currentRate, session.Threshold); changed {
		event.Add(r, event.RateLimitSmoothingDown)
		session.SetAllowance(newAllowance)
		return true, nil
	}

	// Respect configured smoothing interval by updating the session
	session.Touch()

	return false, nil
}

func increaseRateAllowance(session *apidef.RateLimitSmoothing, currentRate int64, maxAllowedRate int64) (int64, bool) {
	step := float64(session.Allowance) - session.Trigger*float64(session.Step)
	newAllowance := session.Allowance + session.Step
	if float64(currentRate) >= step {
		// clamp to the max rate
		if newAllowance > maxAllowedRate {
			newAllowance = maxAllowedRate
		}
		return newAllowance, newAllowance != session.Allowance
	}
	return session.Allowance, false
}

func decreaseRateAllowance(session *apidef.RateLimitSmoothing, currentRate int64, minAllowedRate int64) (int64, bool) {
	newAllowance := session.Allowance - session.Step
	step := float64(newAllowance) - session.Trigger*float64(session.Step)
	if float64(currentRate) <= step {
		if newAllowance < minAllowedRate {
			newAllowance = minAllowedRate
		}
		return newAllowance, newAllowance != session.Allowance
	}
	return session.Allowance, false
}
