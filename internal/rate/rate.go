package rate

import (
	"strings"

	"github.com/TykTechnologies/tyk/internal/rate/limiter"
)

var (
	// ErrLimitExhausted is returned when the request should be blocked.
	ErrLimitExhausted = limiter.ErrLimitExhausted
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

// Prefix is a utility function to generate rate limiter redis key names.
func Prefix(params ...string) string {
	var res strings.Builder
	var written int

	for _, p := range params {
		p = strings.Trim(p, "-")
		if p == "" {
			continue
		}

		if written == 0 {
			res.Write([]byte(p))
			written++
			continue
		}

		res.Write([]byte("-"))
		res.Write([]byte(p))
	}
	return res.String()
}
