package config

import (
	"fmt"
)

// RateLimit contains flags and configuration for controlling rate limiting behaviour.
// It is embedded in the main config structure.
type RateLimit struct {
	// EnableFixedWindow enables fixed window rate limiting.
	EnableFixedWindowRateLimiter bool `json:"enable_fixed_window_rate_limiter"`

	// Redis based rate limiter with sliding log. Provides 100% rate limiting accuracy, but require two additional Redis roundtrips for each request.
	EnableRedisRollingLimiter bool `json:"enable_redis_rolling_limiter"`

	// To enable, set to `true`. The sentinel-based rate limiter delivers a smoother performance curve as rate-limit calculations happen off-thread, but a stricter time-out based cool-down for clients. For example, when a throttling action is triggered, they are required to cool-down for the period of the rate limit.
	// Disabling the sentinel based rate limiter will make rate-limit calculations happen on-thread and therefore offers a staggered cool-down and a smoother rate-limit experience for the client.
	// For example, you can slow your connection throughput to regain entry into your rate limit. This is more of a “throttle” than a “block”.
	// The standard rate limiter offers similar performance as the sentinel-based limiter. This is disabled by default.
	EnableSentinelRateLimiter bool `json:"enable_sentinel_rate_limiter"`

	// EnableRateLimitSmoothing enables or disables rate limit smoothing. The rate smoothing is only supported on the
	// Redis Rate Limiter, or the Sentinel Rate Limiter, as both algorithms implement a sliding log.
	EnableRateLimitSmoothing bool `json:"enable_rate_limit_smoothing"`

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

// String returns a readable setting for the rate limiter in effect.
func (r *RateLimit) String() string {
	info := "using transactions"
	if r.EnableNonTransactionalRateLimiter {
		info = "using pipeline"
	}

	if r.EnableFixedWindowRateLimiter {
		return "Fixed Window Rate Limiter enabled"
	}

	// Smoothing check is here, because the rate limiters above this line
	// do not support smoothing. Smoothing is applied for RRL/Sentinel.
	if r.EnableRateLimitSmoothing {
		info = info + ", with smoothing"
	}

	if r.EnableRedisRollingLimiter {
		return fmt.Sprintf("Redis Rate Limiter enabled (%s)", info)
	}

	if r.EnableSentinelRateLimiter {
		return fmt.Sprintf("Redis Sentinel Rate Limiter enabled (%s)", info)
	}

	if r.DRLEnableSentinelRateLimiter {
		return fmt.Sprintf("DRL with Redis Sentinel Rate Limiter enabled (%s)", info)
	}

	return fmt.Sprintf("DRL with Redis Rate Limiter enabled (%s)", info)
}
