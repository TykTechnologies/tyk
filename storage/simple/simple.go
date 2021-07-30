package simple

import (
	"github.com/dgraph-io/badger/v3"
)

type Simple struct {
	db *badger.DB
}
