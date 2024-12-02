package user

import (
	clone "github.com/huandu/go-clone"

	"github.com/TykTechnologies/tyk/internal/cache"
)

// SessionCache is a typed cache.Repository implementation.
type SessionCache interface {
	Get(string) (*SessionState, bool)
	Set(string, SessionState, int64)
	Delete(string)
	Count() int
	Flush()
}

type sessionCache struct {
	cache cache.Repository
}

// NewSessionCache creates a new SessionCache object.
func NewSessionCache() SessionCache {
	return &sessionCache{
		cache: cache.New(10, 5),
	}
}

// Get retrieves the session state cache for a key.
//
// Repeated calls to Get return unique allocations of *SessionState.
// If the cache for the key doesn't exist, nil and false are returned.
func (s *sessionCache) Get(key string) (*SessionState, bool) {
	data, ok := s.cache.Get(key)
	if !ok {
		return nil, false
	}

	sess, ok := data.(SessionState)
	if !ok {
		return nil, false
	}

	cloned, ok := clone.Clone(sess).(SessionState)
	if !ok {
		return nil, false
	}
	return &cloned, true
}

// Set stores provided SessionState into cache with respective ttl, in seconds.
// If the TTL is 0 or below, the default TTL will be used, see internal/cache.
func (s *sessionCache) Set(key string, sess SessionState, ttl int64) {
	s.cache.Set(key, sess, ttl)
}

// Delete deletes a key from the cache.
func (s *sessionCache) Delete(key string) {
	s.cache.Delete(key)
}

// Count returns the number of items in the cache.
func (s *sessionCache) Count() int {
	return s.cache.Count()
}

// Flush clears the cache.
func (s *sessionCache) Flush() {
	s.cache.Flush()
}
