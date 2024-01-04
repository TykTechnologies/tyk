package config

// RateLimit contains flags and configuration for controlling rate limiting behaviour.
// It is embedded in the main config structure.
type RateLimit struct {
	// EnableLeakyBucketRateLimiter enables leaky bucket rate limiting.
	//
	// LeakyBucket will delay requests so they are processed in a FIFO
	// style queue, ensuring a constant request rate and smoothing out
	// traffic spikes. This comes at some cost to gateway instances, as
	// the connections would be held for a longer time, instead of
	// blocking the requests when they go over the defined rate limits.
	EnableLeakyBucketRateLimiter bool `json:"enable_leaky_bucket_rate_limiter"`

	// Redis based rate limiter with fixed window. Provides 100% rate limiting accuracy, but require two additional Redis roundtrip for each request.
	EnableRedisRollingLimiter bool `json:"enable_redis_rolling_limiter"`

	// To enable, set to `true`. The sentinel-based rate limiter delivers a smoother performance curve as rate-limit calculations happen off-thread, but a stricter time-out based cool-down for clients. For example, when a throttling action is triggered, they are required to cool-down for the period of the rate limit.
	// Disabling the sentinel based rate limiter will make rate-limit calculations happen on-thread and therefore offers a staggered cool-down and a smoother rate-limit experience for the client.
	// For example, you can slow your connection throughput to regain entry into your rate limit. This is more of a “throttle” than a “block”.
	// The standard rate limiter offers similar performance as the sentinel-based limiter. This is disabled by default.
	EnableSentinelRateLimiter bool `json:"enable_sentinel_rate_limiter"`

	// An enhancement for the Redis and Sentinel rate limiters, that offers a significant improvement in performance by not using transactions on Redis rate-limit buckets.
	EnableNonTransactionalRateLimiter bool `json:"enable_non_transactional_rate_limiter"`

	// How frequently a distributed rate limiter synchronises information between the Gateway nodes. Default: 2 seconds.
	DRLNotificationFrequency int `json:"drl_notification_frequency"`

	// A distributed rate limiter is inaccurate on small rate limits, and it will fallback to a Redis or Sentinel rate limiter on an individual user basis, if its rate limiter lower then threshold.
	// A Rate limiter threshold calculated using the following formula: `rate_threshold = drl_threshold * number_of_gateways`.
	// So you have 2 Gateways, and your threshold is set to 5, if a user rate limit is larger than 10, it will use the distributed rate limiter algorithm.
	// Default: 5
	DRLThreshold float64 `json:"drl_threshold"`

	// Controls which algorthm to use as a fallback when your distributed rate limiter can't be used.
	DRLEnableSentinelRateLimiter bool `json:"drl_enable_sentinel_rate_limiter"`
}
