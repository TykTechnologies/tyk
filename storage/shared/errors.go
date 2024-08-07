package shared

import "errors"

// ErrKeyNotFound is a standard error for when a key is not found in the storage engine
var ErrKeyNotFound = errors.New("key not found")
var ErrMDCBConnectionLost = errors.New("mdcb connection is lost")
