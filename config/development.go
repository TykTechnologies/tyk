//go:build dev
// +build dev

package config

// DevelopmentConfig extends Config for development builds.
type DevelopmentConfig struct {
	// EnableLeakyBucketRateLimiter enables leaky bucket rate limiting.
	//
	// LeakyBucket will delay requests so they are processed in a FIFO
	// style queue, ensuring a constant request rate and smoothing out
	// traffic spikes. This comes at some cost to gateway instances, as
	// the connections would be held for a longer time, instead of
	// blocking the requests when they go over the defined rate limits.
	EnableLeakyBucketRateLimiter bool `json:"enable_leaky_bucket_rate_limiter"`

	// EnableTokenBucket enables token bucket rate limiting.
	EnableTokenBucketRateLimiter bool `json:"enable_token_bucket_rate_limiter"`

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
