package storage

import (
	"time"

	"github.com/dgraph-io/badger/v3"
)

var _ RateLimit = (*rate)(nil)

// rate implements SetRollingWindow and GetRollingWindow
type rate struct {
	db *badger.DB
}

func (r *rate) SetRollingWindow(key string, per int64, _ string, _ bool) (total int, result []interface{}) {
	rightnow := time.Now()
	onePeriodAgo := rightnow.Add(time.Duration(-1*per) * time.Second)
	err := r.db.Update(func(txn *badger.Txn) error {
		from := timestamp(onePeriodAgo)
		it := txn.NewKeyIterator([]byte(key), badger.IteratorOptions{
			AllVersions: true,
		})
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			e := it.Item()
			if e.IsDeletedOrExpired() || e.ExpiresAt() < from {
				continue
			}
			total += 1
			result = append(result, struct{}{})
		}
		e := badger.NewEntry([]byte(key), []byte{})
		e.WithTTL(time.Duration(per) * time.Second)
		return txn.SetEntry(e)
	})
	if err != nil {
		return 0, nil
	}
	return
}

func timestamp(ts time.Time) uint64 {
	return uint64(ts.Unix())
}

// GetRollingWindow is like SetRollingWindow except we don't set the key to
// increment the window. We just retrieve elements in the window.
func (r *rate) GetRollingWindow(key string, per int64, pipeline bool) (total int, result []interface{}) {
	rightnow := time.Now()
	onePeriodAgo := rightnow.Add(time.Duration(-1*per) * time.Second)
	err := r.db.View(func(txn *badger.Txn) error {
		from := timestamp(onePeriodAgo)
		it := txn.NewKeyIterator([]byte(key), badger.IteratorOptions{
			AllVersions: true,
		})
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			e := it.Item()
			if e.IsDeletedOrExpired() || e.ExpiresAt() < from {
				continue
			}
			total += 1
			result = append(result, struct{}{})
		}
		return nil
	})
	if err != nil {
		return 0, nil
	}
	return
}
