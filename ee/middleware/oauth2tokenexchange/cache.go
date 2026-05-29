//go:build ee || dev

package oauth2tokenexchange

import (
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

type singleFlightCache struct {
	inner oauth2common.ExchangeCache
	group singleflight.Group
}

func newSingleFlightCache(inner oauth2common.ExchangeCache) *singleFlightCache {
	return &singleFlightCache{inner: inner}
}

type sfResult struct {
	token string
	ttl   time.Duration
}

// GetOrFetch returns the cached token and whether it was a cache hit.
// hit=true means the token came from the cache (fast path).
// hit=false means a fresh fetch was needed — both the singleflight leader
// and any concurrent followers that waited on the same key get hit=false.
func (c *singleFlightCache) GetOrFetch(key string, fetch func() (string, time.Duration, error)) (token string, ttlRemaining time.Duration, hit bool, err error) {
	if token, remaining, miss := c.inner.Get(key); !miss {
		return token, remaining, true, nil
	}
	v, err, _ := c.group.Do(key, func() (any, error) {
		tok, ttl, fetchErr := fetch()
		if fetchErr != nil {
			return nil, fetchErr
		}
		c.inner.Set(key, tok, ttl)
		return sfResult{tok, ttl}, nil
	})
	if err != nil {
		return "", 0, false, err
	}
	r := v.(sfResult)
	return r.token, r.ttl, false, nil
}
