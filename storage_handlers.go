package main

import (
	"encoding/hex"
	"errors"

	"github.com/spaolacci/murmur3"

	"github.com/TykTechnologies/tyk/config"
)

// errKeyNotFound is a standard error for when a key is not found in the storage engine
var errKeyNotFound = errors.New("key not found")

// StorageHandler is a standard interface to a storage backend,
// used by AuthorisationManager to read and write key values to the backend
type StorageHandler interface {
	GetKey(string) (string, error) // Returned string is expected to be a JSON object (SessionState)
	GetRawKey(string) (string, error)
	SetKey(string, string, int64) error // Second input string is expected to be a JSON object (SessionState)
	SetRawKey(string, string, int64) error
	GetExp(string) (int64, error) // Returns expiry of a key
	GetKeys(string) []string
	DeleteKey(string) bool
	DeleteRawKey(string) bool
	Connect() bool
	GetKeysAndValues() map[string]string
	GetKeysAndValuesWithFilter(string) map[string]string
	DeleteKeys([]string) bool
	Decrement(string)
	IncrememntWithExpire(string, int64) int64
	SetRollingWindow(string, int64, string) (int, []interface{})
	SetRollingWindowPipeline(string, int64, string) (int, []interface{})
	GetSet(string) (map[string]string, error)
	AddToSet(string, string)
	AppendToSet(string, string)
	GetAndDeleteSet(string) []interface{}
	RemoveFromSet(string, string)
	DeleteScanMatch(string) bool
}

func doHash(in string) string {
	h := murmur3.New32()
	h.Write([]byte(in))
	return hex.EncodeToString(h.Sum(nil))
}

//Public function for use in classes that bypass elements of the storage manager
func publicHash(in string) string {
	if !config.Global.HashKeys {
		// Not hashing? Return the raw key
		return in
	}

	return doHash(in)
}
