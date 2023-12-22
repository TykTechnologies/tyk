//go:build dev
// +build dev

package config

// DevelopmentConfig extends Config for development builds.
type DevelopmentConfig struct {
	// EnableTokenBucket enables token bucket rate limiting.
	EnableTokenBucketRateLimiter bool `json:"enable_token_bucket_rate_limiter"`

	// EnableFixedWindow enables fixed window rate limiting.
	EnableFixedWindowRateLimiter bool `json:"enable_fixed_window_rate_limiter"`

	// EnableSlidingWindow enables sliding window rate limiting.
	EnableSlidingWindowRateLimiter bool `json:"enable_sliding_window_rate_limiter"`
}
