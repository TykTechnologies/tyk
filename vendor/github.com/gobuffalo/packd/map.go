package packd

import (
	"sort"
	"sync"
)

// ByteMap wraps sync.Map and uses the following types:
// key:   string
// value: []byte
type ByteMap struct {
	data sync.Map
}

// Delete the key from the map
func (m *ByteMap) Delete(key string) {
	m.data.Delete(key)
}

// Load the key from the map.
// Returns []byte or bool.
// A false return indicates either the key was not found
// or the value is not of type []byte
func (m *ByteMap) Load(key string) ([]byte, bool) {
	i, ok := m.data.Load(key)
	if !ok {
		return []byte(``), false
	}
	s, ok := i.([]byte)
	return s, ok
}

// LoadOrStore will return an existing key or
// store the value if not already in the map
func (m *ByteMap) LoadOrStore(key string, value []byte) ([]byte, bool) {
	i, _ := m.data.LoadOrStore(key, value)
	s, ok := i.([]byte)
	return s, ok
}

// Range over the []byte values in the map
func (m *ByteMap) Range(f func(key string, value []byte) bool) {
	m.data.Range(func(k, v interface{}) bool {
		key, ok := k.(string)
		if !ok {
			return false
		}
		value, ok := v.([]byte)
		if !ok {
			return false
		}
		return f(key, value)
	})
}

// Store a []byte in the map
func (m *ByteMap) Store(key string, value []byte) {
	m.data.Store(key, value)
}

// Keys returns a list of keys in the map
func (m *ByteMap) Keys() []string {
	var keys []string
	m.Range(func(key string, value []byte) bool {
		keys = append(keys, key)
		return true
	})
	sort.Strings(keys)
	return keys
}
