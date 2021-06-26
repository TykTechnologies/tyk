package kv

import "errors"

// ErrKeyNotFound is an error meant when a key doesn't exists in the
// storage backend
var ErrKeyNotFound = errors.New("key not found")

// Store is a standard interface to a KV backend
type Store interface {
	Get(key string) (string, error)
}
