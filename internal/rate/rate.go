package rate

import (
	"github.com/TykTechnologies/tyk/internal/rate/limiter"
)

var (
	// ErrLimitExhausted is returned when the request should be blocked.
	ErrLimitExhausted = limiter.ErrLimitExhausted

	// Prefix is a utility function to generate rate limiter redis key names.
	Prefix = limiter.Prefix
)

// The following constants enumerate implemented rate limiters.
const (
	LimitLeakyBucket   string = "leaky-bucket"
	LimitTokenBucket   string = "token-bucket"
	LimitFixedWindow   string = "fixed-window"
	LimitSlidingWindow string = "sliding-window"
)

const (
	// LimiterKeyPrefix serves as a standard prefix for generating rate limit keys.
	LimiterKeyPrefix = "rate-limit-"
)
