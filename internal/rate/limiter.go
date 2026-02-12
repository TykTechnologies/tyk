package rate

import (
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/rate/limiter"
	"github.com/TykTechnologies/tyk/internal/redis"
	"github.com/TykTechnologies/tyk/user"
)

// Limiter returns the appropriate rate limiter as configured by gateway.
func Limiter(gwConfig *config.Config, rClient redis.UniversalClient) limiter.Func {
	name, ok := LimiterKind(gwConfig)
	if !ok {
		return nil
	}

	res := limiter.NewLimiter(rClient)

	switch name {
	case LimitLeakyBucket:
		return res.LeakyBucket
	case LimitTokenBucket:
		return res.TokenBucket
	case LimitFixedWindow:
		return res.FixedWindow
	case LimitSlidingWindow:
		return res.SlidingWindow
	}

	return nil
}

// LimiterKey returns a redis key name based on passed parameters.
// The key should be post-fixed if multiple keys are required (sentinel).
func LimiterKey(currentSession *user.SessionState, rateScope string, key string, useCustomKey bool) string {
	if !useCustomKey && !currentSession.KeyHashEmpty() {
		return Prefix(LimiterKeyPrefix, rateScope, currentSession.KeyHash())
	}

	return Prefix(LimiterKeyPrefix, rateScope, key)
}
