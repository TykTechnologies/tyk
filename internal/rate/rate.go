package rate

import (
	"github.com/TykTechnologies/tyk/internal/rate/limiter"
)

var ErrLimitExhausted = limiter.ErrLimitExhausted

var Prefix = limiter.Prefix

const (
	LimitLeakyBucket   string = "leaky-bucket"
	LimitTokenBucket   string = "token-bucket"
	LimitFixedWindow   string = "fixed-window"
	LimitSlidingWindow string = "sliding-window"
)
