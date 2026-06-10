package gateway

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeStore is a minimal in-memory storage.Handler for tests.
type fakeStore struct {
	mu  sync.Mutex
	kv  map[string]string
	exp map[string]int64
}

func newFakeStore() *fakeStore {
	return &fakeStore{kv: make(map[string]string), exp: make(map[string]int64)}
}

var errNotFound = errors.New("not found")

func (f *fakeStore) GetRawKey(key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.kv[key]
	if !ok {
		return "", errNotFound
	}
	return v, nil
}

func (f *fakeStore) SetRawKey(key, val string, ttl int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kv[key] = val
	f.exp[key] = ttl
	return nil
}

func (f *fakeStore) GetExp(key string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.exp[key]
	if !ok {
		return 0, errNotFound
	}
	return v, nil
}

// Stub all other storage.Handler methods.
func (f *fakeStore) GetKey(string) (string, error)                       { return "", nil }
func (f *fakeStore) GetMultiKey([]string) ([]string, error)              { return nil, nil }
func (f *fakeStore) SetKey(string, string, int64) error                  { return nil }
func (f *fakeStore) SetExp(string, int64) error                          { return nil }
func (f *fakeStore) GetKeys(string) []string                             { return nil }
func (f *fakeStore) DeleteKey(string) bool                               { return false }
func (f *fakeStore) DeleteAllKeys() bool                                 { return false }
func (f *fakeStore) DeleteRawKey(string) bool                            { return false }
func (f *fakeStore) DeleteRawKeys([]string) bool                         { return false }
func (f *fakeStore) Connect() bool                                       { return true }
func (f *fakeStore) GetKeysAndValues() map[string]string                 { return nil }
func (f *fakeStore) GetKeysAndValuesWithFilter(string) map[string]string { return nil }
func (f *fakeStore) DeleteKeys([]string) bool                            { return false }
func (f *fakeStore) Decrement(string)                                    {}
func (f *fakeStore) IncrememntWithExpire(string, int64) int64            { return 0 }
func (f *fakeStore) SetRollingWindow(string, int64, string, bool) (int, []interface{}) {
	return 0, nil
}
func (f *fakeStore) GetRollingWindow(string, int64, bool) (int, []interface{}) { return 0, nil }
func (f *fakeStore) GetSet(string) (map[string]string, error)                  { return nil, nil }
func (f *fakeStore) AddToSet(string, string)                                   {}
func (f *fakeStore) GetAndDeleteSet(string) []interface{}                      { return nil }
func (f *fakeStore) RemoveFromSet(string, string)                              {}
func (f *fakeStore) DeleteScanMatch(string) bool                               { return false }
func (f *fakeStore) GetKeyPrefix() string                                      { return "" }
func (f *fakeStore) AddToSortedSet(string, string, float64)                    {}
func (f *fakeStore) GetSortedSetRange(string, string, string) ([]string, []float64, error) {
	return nil, nil, nil
}
func (f *fakeStore) RemoveSortedSetRange(string, string, string) error   { return nil }
func (f *fakeStore) GetListRange(string, int64, int64) ([]string, error) { return nil, nil }
func (f *fakeStore) RemoveFromList(string, string) error                 { return nil }
func (f *fakeStore) AppendToSet(string, string)                          {}
func (f *fakeStore) Exists(string) (bool, error)                         { return false, nil }

func TestRedisExchangeCache_MissOnEmpty(t *testing.T) {
	c := newRedisExchangeCache(newFakeStore(), "secret")
	token, ttl, miss := c.Get("no-such-key")
	assert.True(t, miss)
	assert.Empty(t, token)
	assert.Zero(t, ttl)
}

func TestRedisExchangeCache_GetSetRoundTrip(t *testing.T) {
	c := newRedisExchangeCache(newFakeStore(), "secret")
	c.Set("k1", "my-token", 60*time.Second)
	token, _, miss := c.Get("k1")
	require.False(t, miss)
	assert.Equal(t, "my-token", token)
}

func TestRedisExchangeCache_GetReturnsRemainingTTL(t *testing.T) {
	// Get must surface the entry's remaining lifetime so callers can log/act on
	// it. This holds only when the value and its TTL live under the same key —
	// the store must apply no extra prefix/hashing to the raw key.
	c := newRedisExchangeCache(newFakeStore(), "secret")
	c.Set("k1", "my-token", 60*time.Second)

	_, ttl, miss := c.Get("k1")
	require.False(t, miss)
	assert.Equal(t, 60*time.Second, ttl)
}

func TestRedisExchangeCache_EncryptedAtRest(t *testing.T) {
	store := newFakeStore()
	c := newRedisExchangeCache(store, "secret")
	c.Set("k1", "plaintext-token", 60*time.Second)

	raw, err := store.GetRawKey("k1")
	require.NoError(t, err)
	assert.NotEqual(t, "plaintext-token", raw, "stored value must be encrypted, not plaintext")
}

func TestRedisExchangeCache_ZeroTTLNotStored(t *testing.T) {
	store := newFakeStore()
	c := newRedisExchangeCache(store, "secret")
	c.Set("k1", "my-token", 0)
	_, _, miss := c.Get("k1")
	assert.True(t, miss)
}

func TestRedisExchangeCache_SubSecondTTLRoundsUp(t *testing.T) {
	// A positive sub-second TTL must not floor to 0: Redis treats a 0 expiry as
	// "no expiry", which would cache a near-expired token forever.
	store := newFakeStore()
	c := newRedisExchangeCache(store, "secret")
	c.Set("k1", "my-token", 400*time.Millisecond)

	exp, err := store.GetExp("k1")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, exp, int64(1))
}

// failingSetStore makes SetRawKey fail to exercise the cache-write error path.
type failingSetStore struct{ *fakeStore }

func (f *failingSetStore) SetRawKey(string, string, int64) error {
	return errors.New("redis down")
}

func TestRedisExchangeCache_SetErrorIsNonFatal(t *testing.T) {
	c := newRedisExchangeCache(&failingSetStore{newFakeStore()}, "secret")
	// A failed cache write must not panic and must leave no entry behind.
	c.Set("k1", "my-token", 60*time.Second)
	_, _, miss := c.Get("k1")
	assert.True(t, miss)
}
