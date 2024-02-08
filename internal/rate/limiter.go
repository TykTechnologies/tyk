package rate

import (
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/rate/limiter"
	"github.com/TykTechnologies/tyk/internal/redis"
)

func Limiter(gwConfig *config.Config, redis redis.UniversalClient) limiter.LimiterFunc {
	name, ok := LimiterKind(gwConfig)
	if !ok {
		return nil
	}

	res := limiter.NewLimiter(name, redis)

	switch {
	case name == LimitLeakyBucket:
		return res.LeakyBucket
	case name == LimitTokenBucket:
		return res.TokenBucket
	case name == LimitFixedWindow:
		return res.FixedWindow
	case name == LimitSlidingWindow:
		return res.SlidingWindow
	}

	return nil
}
