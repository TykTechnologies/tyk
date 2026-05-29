//go:build ee || dev

package oauth2tokenexchange

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCache is a simple in-memory ExchangeCache for tests.
type fakeCache struct {
	mu    sync.Mutex
	items map[string]string
}

func (f *fakeCache) Get(key string) (string, time.Duration, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.items[key]
	if !ok {
		return "", 0, true
	}
	return v, time.Minute, false
}

func (f *fakeCache) Set(key string, token string, _ time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[key] = token
}

func TestSingleFlightCache_HitDoesNotCallFetch(t *testing.T) {
	fc := &fakeCache{items: map[string]string{"k": "tok"}}
	sfc := newSingleFlightCache(fc)
	calls := int32(0)
	fetch := func() (string, time.Duration, error) {
		atomic.AddInt32(&calls, 1)
		return "new", time.Minute, nil
	}
	token, _, hit, err := sfc.GetOrFetch("k", fetch)
	require.NoError(t, err)
	assert.Equal(t, "tok", token)
	assert.True(t, hit)
	assert.Equal(t, int32(0), atomic.LoadInt32(&calls))
}

func TestSingleFlightCache_MissCallsFetch(t *testing.T) {
	fc := &fakeCache{items: map[string]string{}}
	sfc := newSingleFlightCache(fc)
	calls := int32(0)
	fetch := func() (string, time.Duration, error) {
		atomic.AddInt32(&calls, 1)
		return "fetched-token", time.Minute, nil
	}
	token, _, hit, err := sfc.GetOrFetch("k", fetch)
	require.NoError(t, err)
	assert.Equal(t, "fetched-token", token)
	assert.False(t, hit)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls))

	// Second call should hit the cache now.
	token2, _, hit2, err := sfc.GetOrFetch("k", fetch)
	require.NoError(t, err)
	assert.Equal(t, "fetched-token", token2)
	assert.True(t, hit2)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "fetch not called again after cache population")
}

// missCountingCache wraps fakeCache and signals on getCalled whenever Get returns a miss.
// Used to synchronise concurrent tests: wait for N misses before releasing the fetch.
type missCountingCache struct {
	fakeCache
	getCalled chan struct{}
}

func (c *missCountingCache) Get(key string) (string, time.Duration, bool) {
	tok, ttl, miss := c.fakeCache.Get(key)
	if miss {
		c.getCalled <- struct{}{}
	}
	return tok, ttl, miss
}

func TestSingleFlightCache_ConcurrentFollowerReportsMiss(t *testing.T) {
	// Regression test: a singleflight follower (goroutine that arrives while the
	// leader is already fetching) must report hit=false, not hit=true.
	//
	// Synchronisation:
	//   getCalled is signalled by every Get that returns a miss. We wait for
	//   exactly two miss signals before releasing the fetch, which guarantees
	//   both goroutines have called Get → missed → entered group.Do before the
	//   leader returns. The follower is therefore a true singleflight waiter,
	//   not a cache hit.
	getCalled := make(chan struct{}, 2)
	fc := &missCountingCache{
		fakeCache: fakeCache{items: map[string]string{}},
		getCalled: getCalled,
	}
	sfc := newSingleFlightCache(fc)

	proceedFetch := make(chan struct{})
	fetch := func() (string, time.Duration, error) {
		<-proceedFetch
		return "tok", time.Minute, nil
	}

	leaderHit := make(chan bool, 1)
	followerHit := make(chan bool, 1)

	go func() {
		_, _, hit, _ := sfc.GetOrFetch("k", fetch)
		leaderHit <- hit
	}()
	go func() {
		_, _, hit, _ := sfc.GetOrFetch("k", fetch)
		followerHit <- hit
	}()

	// Wait until both goroutines have called Get and found a miss.
	// At this point both are inside group.Do — release the fetch.
	<-getCalled
	<-getCalled
	close(proceedFetch)

	assert.False(t, <-leaderHit, "leader should report miss")
	assert.False(t, <-followerHit, "singleflight follower should report miss, not hit")
}

func TestSingleFlightCache_FetchErrorPropagates(t *testing.T) {
	fc := &fakeCache{items: map[string]string{}}
	sfc := newSingleFlightCache(fc)
	_, _, _, err := sfc.GetOrFetch("k", func() (string, time.Duration, error) {
		return "", 0, errors.New("idp down")
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "idp down")

	// Nothing should be stored on error.
	_, _, miss := fc.Get("k")
	assert.True(t, miss)
}
