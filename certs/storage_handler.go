package certs

import "errors"

// StorageHandlerWrapper is an interface to a storage backend,
// with a wrapped method DeleteKey which returns an error.
// Used for providing compatibility between different storage implementations
// Note: should be removed once we will have a single implementation
// of redis storage
type StorageHandlerWrapper interface {
	GetKey(string) (string, error)
	SetKey(string, string, int64) error
	GetKeys(string) []string
	DeleteKey(string) error
	DeleteScanMatch(string) bool
}

// StorageHandler is a standard interface to a storage backend,
// used by AuthorisationManager to read and write key values to the backend
// uses the same method signatures as in tyk/storage/storage.go
type StorageHandler interface {
	GetKey(string) (string, error)
	SetKey(string, string, int64) error
	GetKeys(string) []string
	DeleteKey(string) bool
	DeleteScanMatch(string) bool
}

type storageWrapper struct {
	s StorageHandler
}

// NewStorageHandler - maps StandardStorageHandler to StorageHandler
func NewStorageHandlerWrapper(s StorageHandler) StorageHandlerWrapper {
	return &storageWrapper{s}
}

func (w *storageWrapper) GetKey(filter string) (string, error) { return w.s.GetKey(filter) }
func (w *storageWrapper) GetKeys(filter string) []string       { return w.s.GetKeys(filter) }
func (w *storageWrapper) DeleteScanMatch(pattern string) bool  { return w.s.DeleteScanMatch(pattern) }

func (w *storageWrapper) SetKey(keyName, session string, timeout int64) error {
	return w.s.SetKey(keyName, session, timeout)
}

func (w *storageWrapper) DeleteKey(key string) error {
	if w.s.DeleteKey(key) {
		return nil
	}
	return errors.New("could not delete key")
}
