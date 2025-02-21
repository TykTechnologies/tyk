package kv

import "errors"

var (
	// ErrKeyNotFound is an error meant when a key doesn't exists in the
	// storage backend
	ErrKeyNotFound = errors.New("key not found")
)

// Store is a standard interface to a KV backend
type Store interface {
	Get(key string) (string, error)
	// Put writes a value to the KV store
	Put(key string, value string) error
}
