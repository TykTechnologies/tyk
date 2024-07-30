package healthcheck

import (
	"context"
	"time"
)

// Checker is the interface to implement for a health checker.
type Checker interface {
	Name() string
	Result(ctx context.Context) error
}

// Response is the aggregated checks run for all checks.
type Response struct {
	// Status is the aggregated status over all components.
	Status CheckStatus `json:"status"`
	// StatusCode is the HTTP response code for the result.
	StatusCode int `json:"status_code"`
	// Components contain all health check result states.
	Components []CheckResult `json:"components,omitempty"`
}

// CheckResult represents the result of running the check.
type CheckResult struct {
	// Name is the name of the check.
	Name string `json:"name"`
	// Status is the status of the check.
	Status CheckStatus `json:"status"`
	// ObservationTS is the timestamp the result was made.
	ObservationTS time.Time `json:"observation_ts"`
}

// NewCheckResult creates a new CheckResult record.
func NewCheckResult(name string, status CheckStatus) CheckResult {
	return CheckResult{
		Name:          name,
		Status:        status,
		ObservationTS: time.Now(),
	}
}

// CheckStatus holds the status of a check result.
type CheckStatus string

const (
	// StatusPass is a passing health check.
	StatusPass CheckStatus = "pass"
	// StatusWarn is a failing optional health check.
	StatusWarn CheckStatus = "warn"
	// StatusFail is a failing required health check.
	StatusFail CheckStatus = "fail"
)

// Logger is the logging interface in use for the runner.
type Logger interface {
	Infof(string, ...any)
	Warnf(string, ...any)
	Errorf(string, ...any)
}
