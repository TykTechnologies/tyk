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

	// EnableRateLimiterStorage enables or disables the configured rate limiter storage under `rate_limiter_storage`.
	EnableRateLimiterStorage bool `json:"enable_rate_limiter_storage"`

	// Storage configures the storage for rate limiters. If unconfigured, will use the default storage.
	// Configuring the storage type as "local", will use non-distributed implementations of rate limiters.
	RateLimiterStorage *StorageOptionsConf `json:"rate_limiter_storage"`
}

// GetRateLimiterStorage will return the storage configuration to use for rate limiters.
func (c *Config) GetRateLimiterStorage() *StorageOptionsConf {
	if !c.EnableRateLimiterStorage {
		return &c.Storage
	}

	if c.RateLimiterStorage == nil {
		return &c.Storage
	}

	return c.RateLimiterStorage
}
