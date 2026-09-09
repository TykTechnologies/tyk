package storage

import (
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
	GetKeyHandler
	GetMultiKeyHandler
	GetRawKeyHandler
	SetKeyHandler
	SetRawKeyHandler
	SetExpHandler
	GetExpHandler
	GetKeysHandler
	DeleteKeyHandler
	DeleteAllKeysHandler
	DeleteRawKeyHandler
	DeleteRawKeysHandler
	ConnectHandler
	GetKeysAndValuesHandler
	GetKeysAndValuesWithFilterHandler
	DeleteKeysHandler
	DecrementHandler
	IncrememntWithExpireHandler
	SetRollingWindowHandler
	GetRollingWindowHandler
	GetSetHandler
	AddToSetHandler
	GetAndDeleteSetHandler
	RemoveFromSetHandler
	DeleteScanMatchHandler
	GetKeyPrefixHandler
	AddToSortedSetHandler
	GetSortedSetRangeHandler
	RemoveSortedSetRangeHandler
	GetListRangeHandler
	RemoveFromListHandler
	AppendToSetHandler
	ExistsHandler
	SetKeyExHandler
	SetRawKeyExHandler
}

type AnalyticsHandler interface {
	Connect() bool
	AppendToSetPipelined(string, [][]byte)
	GetAndDeleteSet(string) []interface{}
	SetExp(string, int64) error   // Set key expiration
	GetExp(string) (int64, error) // Returns expiry of a key
}

type GetKeyHandler interface {
	GetKey(string) (string, error) // Returned string is expected to be a JSON object (user.SessionState)
}

type GetMultiKeyHandler interface {
	GetMultiKey([]string) ([]string, error)
}

type GetRawKeyHandler interface {
	GetRawKey(string) (string, error)
}

type SetKeyHandler interface {
	SetKey(string, string, int64) error // Second input string is expected to be a JSON object (user.SessionState)
}

type SetRawKeyHandler interface {
	SetRawKey(string, string, int64) error
}

type SetExpHandler interface {
	SetExp(string, int64) error // Set key expiration
}

type GetExpHandler interface {
	GetExp(string) (int64, error) // Returns expiry of a key
}

type GetKeysHandler interface {
	GetKeys(string) []string
}

type DeleteKeyHandler interface {
	DeleteKey(string) bool
}

type DeleteAllKeysHandler interface {
	DeleteAllKeys() bool
}

type DeleteRawKeyHandler interface {
	DeleteRawKey(string) bool
}

type DeleteRawKeysHandler interface {
	DeleteRawKeys([]string) bool
}

type ConnectHandler interface {
	Connect() bool
}

type GetKeysAndValuesHandler interface {
	GetKeysAndValues() map[string]string
}

type GetKeysAndValuesWithFilterHandler interface {
	GetKeysAndValuesWithFilter(string) map[string]string
}

type DeleteKeysHandler interface {
	DeleteKeys([]string) bool
}

type DecrementHandler interface {
	Decrement(string)
}

type IncrememntWithExpireHandler interface {
	IncrememntWithExpire(string, int64) int64
}

type SetRollingWindowHandler interface {
	SetRollingWindow(key string, per int64, val string, pipeline bool) (int, []interface{})
}

type GetRollingWindowHandler interface {
	GetRollingWindow(key string, per int64, pipeline bool) (int, []interface{})
}

type GetSetHandler interface {
	GetSet(string) (map[string]string, error)
}

type AddToSetHandler interface {
	AddToSet(string, string)
}

type GetAndDeleteSetHandler interface {
	GetAndDeleteSet(string) []interface{}
}

type RemoveFromSetHandler interface {
	RemoveFromSet(string, string)
}

type DeleteScanMatchHandler interface {
	DeleteScanMatch(string) bool
}

type GetKeyPrefixHandler interface {
	GetKeyPrefix() string
}

type AddToSortedSetHandler interface {
	AddToSortedSet(string, string, float64)
}

type GetSortedSetRangeHandler interface {
	GetSortedSetRange(string, string, string) ([]string, []float64, error)
}

type RemoveSortedSetRangeHandler interface {
	RemoveSortedSetRange(string, string, string) error
}

type GetListRangeHandler interface {
	GetListRange(string, int64, int64) ([]string, error)
}

type RemoveFromListHandler interface {
	RemoveFromList(string, string) error
}

type AppendToSetHandler interface {
	AppendToSet(string, string)
}

type ExistsHandler interface {
	Exists(string) (bool, error)
}

type SetKeyExHandler interface {
	// SetKeyEx sets key if key already exists.
	SetKeyEx(string, string, int64) error
}

type SetRawKeyExHandler interface {
	// SetRawKeyEx sets raw key if key already exists.
	SetRawKeyEx(string, string, int64) error
}
