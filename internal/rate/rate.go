package rate

import (
	"github.com/TykTechnologies/tyk/internal/rate/limiter"
)

var (
	ErrLimitExhausted = limiter.ErrLimitExhausted
	Prefix            = limiter.Prefix
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
