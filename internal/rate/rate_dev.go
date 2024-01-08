//go:build dev
// +build dev

package rate

import (
	"github.com/TykTechnologies/tyk/config"
)

// LimiterKind returns the kind of rate limiter enabled by config.
// This function is used for development builds.
func LimiterKind(c *config.Config) (string, bool) {
	if c.EnableLeakyBucketRateLimiter {
		return LimitLeakyBucket, true
	}
	if c.EnableTokenBucketRateLimiter {
		return LimitTokenBucket, true
	}
	if c.EnableFixedWindowRateLimiter {
		return LimitFixedWindow, true
	}
	if c.EnableSlidingWindowRateLimiter {
		return LimitSlidingWindow, true
	}
	return "", false
}
