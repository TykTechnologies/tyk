package storage

import (
	"errors"
	"fmt"
)

// DummyStorage is a simple in-memory storage structure used for testing or
// demonstration purposes. It simulates a storage system.
type DummyStorage struct {
	Data      map[string]string
	IndexList map[string][]string
}

// NewDummyStorage creates and returns a new instance of DummyStorage.
func NewDummyStorage() *DummyStorage {
	return &DummyStorage{
		Data:      make(map[string]string),
		IndexList: make(map[string][]string),
	}
}

// GetMultiKey retrieves multiple values from the DummyStorage based on a slice of keys.
// It returns a slice of strings containing the values corresponding to each provided key,
// and an error if the operation cannot be completed.
func (s *DummyStorage) GetMultiKey(keys []string) ([]string, error) {
	var values []string
	for _, key := range keys {
		value, ok := s.Data[key]
		if !ok {
			return nil, fmt.Errorf("key not found: %s", key)
		}
		values = append(values, value)
	}
	return values, nil
}

// GetRawKey retrieves the value associated with a given key from the DummyStorage.
// The method accepts a single string as the key and returns the corresponding string value.
// An error is also returned to indicate whether the retrieval was successful.
// Currently, this method is not implemented and will cause a panic if invoked.
func (s *DummyStorage) GetRawKey(key string) (string, error) {
	value, ok := s.Data[key]
	if !ok {
		return "", fmt.Errorf("key not found: %s", key)
	}
	return value, nil
}

// SetRawKey stores a value with a specified key in the DummyStorage.
// It takes three parameters: the key and value as strings, and an expiry time as int64.
// The expiry time could be used to simulate time-sensitive data storage or caching behavior.
// Currently, this method is not implemented and will trigger a panic if it is called.
// TODO: Proper implementation is needed for this method to handle data storage, or manage
func (s *DummyStorage) SetRawKey(string, string, int64) error {
	panic("implement me")
}

// SetExp updates the expiration time of a specific key in the DummyStorage.
// This method accepts two parameters: a string representing the key, and an int64
// indicating the new expiration time.
func (s *DummyStorage) SetExp(string, int64) error {
	panic("implement me")
}

// GetExp retrieves the expiration time of a specific key from the DummyStorage.
// This method accepts a string parameter representing the key and returns an int64
// which is the expiration time associated with that key, along with an error.
func (s *DummyStorage) GetExp(string) (int64, error) {
	panic("implement me")
}

// DeleteAllKeys removes all keys and their associated data from the DummyStorage.
// This method is intended to provide a way to clear the entire storage, which can
// be particularly useful in testing scenarios to ensure a clean state before tests.
func (s *DummyStorage) DeleteAllKeys() bool {
	panic("implement me")
}

// DeleteRawKey removes a specified key from DummyStorage, returning success status; not yet implemented.
func (s *DummyStorage) DeleteRawKey(string) bool {
	panic("implement me")
}

// DeleteRawKeys removes a set of raw keys from DummyStorage, returning success status; not yet implemented.
func (s *DummyStorage) DeleteRawKeys([]string) bool { panic("implement me") }

// Connect establishes a connection to the storage backend; not currently implemented.
func (s *DummyStorage) Connect() bool {
	return true
}

// GetKeysAndValues retrieves all key-value pairs from DummyStorage; currently not implemented.
func (s *DummyStorage) GetKeysAndValues() map[string]string {
	panic("implement me")
}

// GetKeysAndValuesWithFilter fetches key-value pairs matching a filter from DummyStorage; not implemented.
func (s *DummyStorage) GetKeysAndValuesWithFilter(string) map[string]string {
	panic("implement me")
}

// DeleteKeys removes a list of keys from DummyStorage, returning a success status; not yet implemented.
func (s *DummyStorage) DeleteKeys([]string) bool {
	panic("implement me")
}

// Decrement reduces the value of a specified key in DummyStorage; implementation pending.
func (s *DummyStorage) Decrement(string) {
	panic("implement me")
}

// IncrememntWithExpire increments the value of a key and sets an expiry; not yet implemented.
func (s *DummyStorage) IncrememntWithExpire(string, int64) int64 {
	panic("implement me")
}

// SetRollingWindow sets a rolling window for a key with specified parameters; implementation pending.
func (s *DummyStorage) SetRollingWindow(string, int64, string, bool) (int, []interface{}) {
	panic("implement me")
}

// GetRollingWindow retrieves data for a specified rolling window; currently not implemented.
func (s *DummyStorage) GetRollingWindow(string, int64, bool) (int, []interface{}) {
	panic("implement me")
}

// GetSet retrieves a set of values associated with a key in DummyStorage; not yet implemented.
func (s *DummyStorage) GetSet(string) (map[string]string, error) {
	panic("implement me")
}

// AddToSet adds a value to a set associated with a key in DummyStorage; implementation pending.
func (s *DummyStorage) AddToSet(string, string) {
	panic("implement me")
}

// GetAndDeleteSet retrieves and then deletes a set associated with a key in DummyStorage; not implemented.
func (s *DummyStorage) GetAndDeleteSet(string) []interface{} {
	panic("implement me")
}

// RemoveFromSet deletes a specific value from a set in DummyStorage; currently not implemented.
func (s *DummyStorage) RemoveFromSet(string, string) {
	panic("implement me")
}

// GetKeyPrefix returns the prefix used for keys in DummyStorage; not yet implemented.
func (s *DummyStorage) GetKeyPrefix() string {
	panic("implement me")
}

// AddToSortedSet inserts a value with a score into a sorted set in DummyStorage; implementation pending.
func (s *DummyStorage) AddToSortedSet(string, string, float64) {
	panic("implement me")
}

// GetSortedSetRange retrieves a range of values and scores from a sorted set in DummyStorage; not implemented.
func (s *DummyStorage) GetSortedSetRange(string, string, string) ([]string, []float64, error) {
	panic("implement me")
}

// RemoveSortedSetRange deletes a range of values from a sorted set in DummyStorage; yet to be implemented.
func (s *DummyStorage) RemoveSortedSetRange(string, string, string) error {
	panic("implement me")
}

// GetKey retrieves the value for a given key from DummyStorage, or an error if not found.
func (s *DummyStorage) GetKey(key string) (string, error) {
	if value, ok := s.Data[key]; ok {
		return value, nil
	}

	return "", errors.New("Not found")
}

// SetKey assigns a value to a key in DummyStorage with an expiration time; returns nil for success.
func (s *DummyStorage) SetKey(key, value string, _ int64) error {
	s.Data[key] = value
	return nil
}

// DeleteKey removes a specified key from DummyStorage, returning true if successful.
func (s *DummyStorage) DeleteKey(key string) bool {
	if _, ok := s.Data[key]; !ok {
		return false
	}

	delete(s.Data, key)
	return true
}

// DeleteScanMatch deletes keys matching a pattern from DummyStorage, returning true if successful.
func (s *DummyStorage) DeleteScanMatch(pattern string) bool {
	if pattern == "*" {
		s.Data = make(map[string]string)
		return true
	}

	return false
}

// RemoveFromList eliminates a specific value from a list within DummyStorage; always returns nil.
func (s *DummyStorage) RemoveFromList(keyName, value string) error {
	for key, keyList := range s.IndexList {
		if key == keyName {
			new := keyList[:]
			newL := 0
			for _, e := range new {
				if e == value {
					continue
				}

				new[newL] = e
				newL++
			}
			new = new[:newL]
			s.IndexList[key] = new
		}
	}

	return nil
}

// GetListRange retrieves a range of list elements from DummyStorage for a specified key; returns an error if not found.
func (s *DummyStorage) GetListRange(keyName string, _, _ int64) ([]string, error) {
	for key := range s.IndexList {
		if key == keyName {
			return s.IndexList[key], nil
		}
	}
	return []string{}, nil
}

// Exists checks if a key exists in either the IndexList or Data in DummyStorage; returns true if found.
func (s *DummyStorage) Exists(keyName string) (bool, error) {
	_, existIndex := s.IndexList[keyName]
	_, existRaw := s.Data[keyName]
	return existIndex || existRaw, nil
}

// AppendToSet adds a new value to the end of a list associated with a key in DummyStorage.
func (s *DummyStorage) AppendToSet(keyName string, value string) {
	s.IndexList[keyName] = append(s.IndexList[keyName], value)
}

// GetKeys retrieves all keys matching a specified pattern from DummyStorage; currently supports only '*'.
func (s *DummyStorage) GetKeys(pattern string) (keys []string) {
	if pattern != "*" {
		return nil
	}

	for k := range s.Data {
		keys = append(keys, k)
	}

	return keys
}
