package user

import (
	"encoding/json"

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

	dataBytes, ok := data.([]byte)
	if !ok {
		return nil, false
	}

	sess := &SessionState{}
	err := json.Unmarshal(dataBytes, sess)
	if err != nil {
		return nil, false
	}

	return sess, true
}

// Set will encode the *SessionState and store it in the cache.
// The ttl value for the object is passed in seconds.
func (s *sessionCache) Set(key string, sess SessionState, ttl int64) {
	data, err := json.Marshal(sess)
	if err != nil {
		return
	}

	s.cache.Set(key, data, ttl)
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
