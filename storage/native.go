package storage

import (
	"github.com/dgraph-io/badger/v3"
)

type Native struct {
	Options
	db *badger.DB
}
