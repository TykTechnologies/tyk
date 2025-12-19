package storage

import (
	"context"
	"errors"

	logger "github.com/TykTechnologies/tyk/log"
)

//go:generate mockgen -destination=./mock/storage.go -package mock . Handler

var log = logger.Get()

// ErrKeyNotFound is a standard error for when a key is not found in the storage engine
var ErrKeyNotFound = errors.New("key not found")

var ErrMDCBConnectionLost = errors.New("mdcb connection is lost")

// Handler is a standard interface to a storage backend, used by
// AuthorisationManager to read and write key values to the backend
type Handler interface {
	GetKey(string) (string, error) // Returned string is expected to be a JSON object (user.SessionState)
	GetMultiKey(context.Context, []string) ([]string, error)
	GetRawMultiKey(context.Context, []string) ([]string, error)
	GetRawKey(string) (string, error)
	SetKey(string, string, int64) error // Second input string is expected to be a JSON object (user.SessionState)
	SetRawKey(string, string, int64) error
	SetExp(string, int64) error   // Set key expiration
	GetExp(string) (int64, error) // Returns expiry of a key
	GetKeys(string) []string
	DeleteKey(string) bool
	DeleteAllKeys() bool
	DeleteRawKey(string) bool
	DeleteRawKeys([]string) bool
	Connect() bool
	GetKeysAndValues() map[string]string
	GetKeysAndValuesWithFilter(string) map[string]string
	DeleteKeys([]string) bool
	Decrement(string)
	IncrememntWithExpire(string, int64) int64
	SetRollingWindow(key string, per int64, val string, pipeline bool) (int, []interface{})
	GetRollingWindow(key string, per int64, pipeline bool) (int, []interface{})
	GetSet(string) (map[string]string, error)
	AddToSet(string, string)
	GetAndDeleteSet(string) []interface{}
	RemoveFromSet(string, string)
	DeleteScanMatch(string) bool
	GetKeyPrefix() string
	AddToSortedSet(string, string, float64)
	GetSortedSetRange(string, string, string) ([]string, []float64, error)
	RemoveSortedSetRange(string, string, string) error
	GetListRange(string, int64, int64) ([]string, error)
	RemoveFromList(string, string) error
	AppendToSet(string, string)
	Exists(string) (bool, error)
}

type AnalyticsHandler interface {
	Connect() bool
	AppendToSetPipelined(string, [][]byte)
	GetAndDeleteSet(string) []interface{}
	SetExp(string, int64) error   // Set key expiration
	GetExp(string) (int64, error) // Returns expiry of a key
}
