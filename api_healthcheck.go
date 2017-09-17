package main

import "github.com/TykTechnologies/tyk/health"

type HealthPrefix = health.HealthPrefix

const (
	Throttle          HealthPrefix = "Throttle"
	QuotaViolation    HealthPrefix = "QuotaViolation"
	KeyFailure        HealthPrefix = "KeyFailure"
	RequestLog        HealthPrefix = "Request"
	BlockedRequestLog HealthPrefix = "BlockedRequest"
)

type HealthChecker = health.HealthChecker
type HealthCheckValues = health.HealthCheckValues

type DefaultHealthChecker = health.DefaultHealthChecker

// reportHealthValue is a shortcut we can use throughout the app to push a health check value
func reportHealthValue(spec *APISpec, counter HealthPrefix, value string) {
	return
}