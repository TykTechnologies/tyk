package healthcheck

import (
	"context"
	"net/http"
)

// Logger is the logging interface in use for the runner.
type Logger interface {
	Infof(string, ...any)
}

// Runner is an object holding Checker implementations.
type Runner struct {
	required []Checker
	optional []Checker
	info     []Checker

	logger Logger
}

// NewRunner creates a new runner for Checkers. It requires
// a passed logger, and optionally takes required checks.
func NewRunner(logger Logger, required ...Checker) *Runner {
	return &Runner{
		logger:   logger,
		required: required,
	}
}

// Require adds a new required Checker to the runner.
// The checks must pass.
func (r *Runner) Require(check ...Checker) {
	r.required = append(r.required, check...)
}

// Optional adds a new optional Checker to the runner.
// If the checks fail, a warning is emitted.
func (r *Runner) Optional(check ...Checker) {
	r.optional = append(r.optional, check...)
}

// Info adds a new info Checker to the runner.
// The checks can fail and get logged.
func (r *Runner) Info(check ...Checker) {
	r.info = append(r.info, check...)
}

// Do will run all health checks sequentially.
func (r *Runner) Do(ctx context.Context) Response {
	resp := Response{
		Status:     StatusPass,
		StatusCode: http.StatusOK,
	}
	for _, check := range r.info {
		if err := check.Result(ctx); err != nil {
			r.logger.Infof("[info] HealthCheck %s reports: %s", err)
		}

		result := NewCheckResult(check.Name(), StatusPass)
		resp.Components = append(resp.Components, result)
	}

	for _, check := range r.optional {
		status := StatusPass
		if err := check.Result(ctx); err != nil {
			status = StatusWarn
			// return HTTP 207 on a failing optional check
			resp.Status = status
			resp.StatusCode = http.StatusMultiStatus
		}

		result := NewCheckResult(check.Name(), status)
		resp.Components = append(resp.Components, result)
	}

	for _, check := range r.required {
		status := StatusPass
		if err := check.Result(ctx); err != nil {
			status = StatusFail
			// return HTTP 503 for a failing required check
			resp.Status = status
			resp.StatusCode = http.StatusServiceUnavailable
		}
		result := NewCheckResult(check.Name(), status)
		resp.Components = append(resp.Components, result)
	}

	return resp
}
