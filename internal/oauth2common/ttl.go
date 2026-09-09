package oauth2common

import "time"

// DefaultSafetyMargin is used when safetyMargin is zero in the cache config.
const DefaultSafetyMargin = 30 * time.Second

// DerivedTTL computes the cache TTL for mode=derived.
// inboundRemaining=0 means the inbound token's remaining lifetime is unknown and is not used as a bound.
func DerivedTTL(expiresIn, inboundRemaining, maxTimeout, safetyMargin time.Duration) time.Duration {
	ttl := expiresIn
	if inboundRemaining > 0 && inboundRemaining < ttl {
		ttl = inboundRemaining
	}
	if maxTimeout > 0 && maxTimeout < ttl {
		ttl = maxTimeout
	}
	return ttl - safetyMargin
}

// StaticTTL computes the cache TTL for mode=static.
// expiresIn=0 means the IdP did not return an expiry and is not used as a bound.
func StaticTTL(timeout, expiresIn, safetyMargin time.Duration) time.Duration {
	ttl := timeout
	if expiresIn > 0 && expiresIn < ttl {
		ttl = expiresIn
	}
	return ttl - safetyMargin
}
