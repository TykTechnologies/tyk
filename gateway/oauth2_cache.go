package gateway

import (
	"math"
	"time"

	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
	"github.com/TykTechnologies/tyk/storage"
)

type redisExchangeCache struct {
	store  storage.Handler
	secret []byte
}

func newRedisExchangeCache(store storage.Handler, secret string) oauth2common.ExchangeCache {
	return &redisExchangeCache{store: store, secret: crypto.GetPaddedString(secret)}
}

func (c *redisExchangeCache) Get(key string) (string, time.Duration, bool) {
	val, err := c.store.GetRawKey(key)
	if err != nil || val == "" {
		return "", 0, true
	}
	token := crypto.Decrypt(c.secret, val)
	if token == "" {
		return "", 0, true
	}
	ttlSec, err := c.store.GetExp(key)
	if err != nil || ttlSec <= 0 {
		return token, 0, false
	}
	return token, time.Duration(ttlSec) * time.Second, false
}

func (c *redisExchangeCache) Set(key string, token string, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	encrypted := crypto.Encrypt(c.secret, token)
	if encrypted == "" {
		return
	}
	// Round up: a sub-second TTL must not floor to 0, which Redis reads as "no
	// expiry" and would cache a near-expired token forever.
	ttlSec := int64(math.Ceil(ttl.Seconds()))
	if err := c.store.SetRawKey(key, encrypted, ttlSec); err != nil {
		log.WithError(err).Warning("token exchange cache: failed to store entry")
	}
}
