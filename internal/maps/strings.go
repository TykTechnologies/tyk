package maps

import "sync"

// StringMap holds a concurrency safe, type safe access to map[string]string.
// Access is protected with a sync.RWMutex, optimized for reads.
type StringMap struct {
	mu   sync.RWMutex
	data map[string]string
}

// NewStringMap returns a new *StringMap.
func NewStringMap() *StringMap {
	return &StringMap{
		data: make(map[string]string),
	}
}

// Set will set a value to a key in the map.
func (s *StringMap) Set(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data[key] = value
}

// Get returns the value, and if it existed in the map.
func (s *StringMap) Get(key string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	v, ok := s.data[key]
	return v, ok
}
