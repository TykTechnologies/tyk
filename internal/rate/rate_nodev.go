//go:build !dev
// +build !dev

package rate

import (
	"github.com/TykTechnologies/tyk/config"
)

// LimiterKind returns the kind of rate limiter enabled by config.
// This function is used for release builds.
func LimiterKind(c *config.Config) (string, bool) {
	if c.EnableFixedWindowRateLimiter {
		return LimitFixedWindow, true
	}
	return "", false
}
