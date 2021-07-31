package simple

import (
	"github.com/dgraph-io/badger/v3"
)

type Simple struct {
	KeyPrefix string
	db        *badger.DB
}
