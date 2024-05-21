package rate

import (
	"fmt"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/event"
)

// Smoothing will process the rate limit smoothing based on passed arguments.
// The first returned value indicates if smoothing was performed. An optionally filled error
// returns any details as to why smoothing wasn't performed for logging purposes.
func Smoothing(r *http.Request, session *apidef.RateLimitSmoothing, key string, currentRate int64, maxAllowedRate int64) (bool, error) {
	// Rate limit smoothing is disabled, no change, no error.
	if !session.Valid() {
		return false, nil
	}

	// Allowance can only be set once per defined interval
	if !session.CanSetAllowance() {
		return false, nil
	}

	var (
		newAllowance int64
		eventName    event.Event
	)

	if float64(currentRate) >= session.Trigger*float64(session.Allowance) {
		eventName = event.RateLimitSmoothingUp
		newAllowance = session.Allowance + session.Rate
	}

	if float64(currentRate) <= session.Trigger*float64(session.Allowance-session.Rate) {
		eventName = event.RateLimitSmoothingDown
		newAllowance = session.Allowance - session.Rate
	}

	if newAllowance == 0 {
		// no smoothing occured
		return false, nil
	}

	if newAllowance > int64(maxAllowedRate) {
		return false, fmt.Errorf("skipping smoothing, new allowance over allowed rate (%d > %d)", newAllowance, maxAllowedRate)
	}

	if newAllowance < session.Threshold {
		return false, fmt.Errorf("skipping smoothing, new allowance less than threshold (%d < %d)", newAllowance, session.Threshold)
	}

	// Update session allowance
	session.SetAllowance(newAllowance)

	// Trigger smoothing events
	event.Add(r, eventName)

	// Let the outside know that smoothing has been done.
	return true, nil
}
