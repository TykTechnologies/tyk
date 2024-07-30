package healthcheck

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Runner is an object holding Checker implementations.
type Runner struct {
	required []Checker
	optional []Checker
	info     []Checker

	logger Logger

	lastResponse     Response
	lastResponseMu   sync.Mutex
	lastResponseTime time.Time

	cacheHits   int64
	cacheMisses int64
}

// NewRunner creates a new runner for Checkers. It requires
// a passed logger, and optionally takes required checks.
func NewRunner(logger Logger, required ...Checker) *Runner {
	return &Runner{
		logger:   logger,
		required: required,
	}
}

// String returns a string with the stats for the runner.
func (r *Runner) String() string {
	hits, misses := atomic.LoadInt64(&r.cacheHits), atomic.LoadInt64(&r.cacheMisses)
	return fmt.Sprintf("runner cache hits: %d, misses: %d", hits, misses)
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
//
// Passing the ttl argument as a non-zero duration will cache the Response
// for that duration. Passing zero will skip caching.
//
// Do not modify the returned Response.
func (r *Runner) Do(ctx context.Context, ttl time.Duration) Response {
	r.lastResponseMu.Lock()
	defer r.lastResponseMu.Unlock()

	shouldUpdate := time.Since(r.lastResponseTime) > ttl
	if shouldUpdate {
		r.lastResponse = r.do(ctx)
		r.lastResponseTime = time.Now()
		atomic.AddInt64(&r.cacheMisses, 1)
	} else {
		atomic.AddInt64(&r.cacheHits, 1)
	}
	return r.lastResponse
}

func (r *Runner) do(ctx context.Context) Response {
	resp := Response{
		Status:     StatusPass,
		StatusCode: http.StatusOK,
	}
	for _, check := range r.info {
		name := check.Name()
		if err := check.Result(ctx); err != nil {
			r.logger.Infof("HealthCheck %s reports: %s", name, err)
		}

		result := NewCheckResult(name, StatusPass)
		resp.Components = append(resp.Components, result)
	}

	for _, check := range r.optional {
		name := check.Name()
		status := StatusPass
		if err := check.Result(ctx); err != nil {
			r.logger.Warnf("HealthCheck %s reports: %s", name, err)

			status = StatusWarn
			// return HTTP 207 on a failing optional check
			resp.Status = status
			resp.StatusCode = http.StatusMultiStatus
		}

		result := NewCheckResult(name, status)
		resp.Components = append(resp.Components, result)
	}

	for _, check := range r.required {
		name := check.Name()
		status := StatusPass
		if err := check.Result(ctx); err != nil {
			r.logger.Errorf("HealthCheck %s reports: %s", name, err)

			status = StatusFail
			// return HTTP 503 for a failing required check
			resp.Status = status
			resp.StatusCode = http.StatusServiceUnavailable
		}
		result := NewCheckResult(name, status)
		resp.Components = append(resp.Components, result)
	}

	return resp
}
