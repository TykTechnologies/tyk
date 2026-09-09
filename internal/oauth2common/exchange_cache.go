package oauth2common

import "time"

// ExchangeCache is the cache interface for token exchange results.
type ExchangeCache interface {
	Get(key string) (token string, ttlRemaining time.Duration, miss bool)
	Set(key string, token string, ttl time.Duration)
}
