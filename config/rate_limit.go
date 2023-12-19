package config

// RateLimit contains flags and configuration to enable rate limiting behaviour.
//
// The rate limit behaviour flags are exclusive. Only one can be enabled at a
// time. If multiple flags are enabled, the rate limiter will be chosen from
// the following priority:
//
// - Leaky Bucket
// - Token Bucket
// - Fixed Window
// - Rolling Window
//
// For example, if both token bucket and fixed window rate limiter flags are
// enabled, the token bucket rate limiter would be used.
type RateLimit struct {
	// EnableLeakyBucket enables leaky bucket rate limiting.
	//
	// LeakyBucket will delay requests so they are processed in a FIFO
	// style queue, ensuring a constant request rate and smoothing out
	// traffic spikes. This comes at some cost to gateway instances, as
	// the connections would be held for a longer time, instead of
	// blocking the requests when they go over the defined rate limits.
	EnableLeakyBucket bool `json:"enable_leaky_bucket"`

	// EnableTokenBucket enables token bucket rate limiting.
	EnableTokenBucket bool `json:"enable_token_bucket"`

	// EnableFixedWindow enables fixed window rate limiting.
	EnableFixedWindow bool `json:"enable_fixed_window"`

	// EnableSlidingWindow enables sliding window rate limiting.
	EnableSlidingWindow bool `json:"enable_sliding_window"`

	// Storage configures the storage for rate limiters. If unconfigured, will use the default storage.
	// Configuring the storage type as "local", will use non-distributed implementations of rate limiters.
	Storage *StorageOptionsConf `json:"storage"`
}
