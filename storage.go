package main

// KeyError is a standard error for when a key is not found in the storage engine
type KeyError struct {}
func (e KeyError) Error() string {
	return "Key not found"
}

// StorageHandler is a standard interface to a storage backend,
// used by AuthorisationManager to read and write key values to the backend
type StorageHandler interface {
	GetKey(string) (string, error) // Returned string is expected to be a JSON object (SessionState)
	SetKey(string, string) // Second input string is expected to be a JSON object (SessionState)
}

// InMemoryStorageManager implements the StorageHandler interface,
// it uses an in-memory map to store sessions, should only be used
// for testing purposes
type InMemoryStorageManager struct {
	Sessions map[string]string
}

// GetKey retrieves the key from the in-memory map
func (s InMemoryStorageManager) GetKey(keyName string) (string, error) {
	value, ok := s.Sessions[keyName]
	if !ok {
		return "", KeyError{}
	} else {
		return value, nil
	}
}

// SetKey updates the in-memory key
func (s InMemoryStorageManager) SetKey(keyName string, sessionState string) {
	s.Sessions[keyName] = sessionState
}
