package main

import (
	"encoding/hex"
	"errors"

	"github.com/spaolacci/murmur3"
	"github.com/TykTechnologies/tyk/storage"
)

type StorageHandler = storage.StorageHandler

// errKeyNotFound is a standard error for when a key is not found in the storage engine
var errKeyNotFound = errors.New("key not found")

func doHash(in string) string {
	h := murmur3.New32()
	h.Write([]byte(in))
	return hex.EncodeToString(h.Sum(nil))
}

//Public function for use in classes that bypass elements of the storage manager
func publicHash(in string) string {
	if !globalConf.HashKeys {
		// Not hashing? Return the raw key
		return in
	}

	return doHash(in)
}
