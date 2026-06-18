package cache

import (
	"time"
)

type Item struct {
	Object     any
	Expiration int64
}

// Returns true if the item has expired.
func (item Item) Expired() bool {
	if item.Expiration <= 0 {
		return false
	}
	return time.Now().UnixNano() > item.Expiration
}
