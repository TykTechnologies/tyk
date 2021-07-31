package storage

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v3"
)

var _ KeyValue = (*kv)(nil)

type kv struct {
	Options
	db *badger.DB
}

func (r *kv) GetKeyPrefix() string {
	return r.KeyPrefix
}

// GetKey will retrieve a key from the database
func (r *kv) GetKey(keyName string) (string, error) {
	value, err := r.get(r.FixKey(keyName))
	if err != nil {
		log.Debug("Error trying to get value:", err)
		return "", ErrKeyNotFound
	}
	return string(value), nil
}

func (r *kv) get(key string) (value []byte, err error) {
	err = r.db.View(func(txn *badger.Txn) error {
		x, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		value, err = x.ValueCopy(nil)
		return err
	})
	return
}

func (r *kv) del(key string) error {
	return r.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
}

func (r *kv) set(key string, value []byte, timeout int64) error {
	return r.db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry([]byte(key), value)
		if timeout != 0 {
			e.WithTTL(time.Duration(timeout) * time.Second)
		}
		return txn.SetEntry(e)
	})
}

func (r *kv) iter(scan string, fn func(txn *badger.Txn, item *badger.Item) error) error {
	return r.db.Update(func(txn *badger.Txn) error {
		o := badger.DefaultIteratorOptions
		if scan == "*" || scan == "" {
			// iterate over all keys
			it := txn.NewIterator(o)
			defer it.Close()
			for it.Rewind(); it.Valid(); it.Next() {
				if err := fn(txn, it.Item()); err != nil {
					return err
				}
			}
			return nil
		}
		prefix := []byte(strings.TrimSuffix(scan, "*"))
		o.Prefix = prefix
		it := txn.NewIterator(o)
		defer it.Close()
		for it.Rewind(); it.ValidForPrefix(prefix); it.Next() {
			if err := fn(txn, it.Item()); err != nil {
				return err
			}
		}
		return nil
	})
}

// GetMultiKey gets multiple keys from the database
func (r *kv) GetMultiKey(keys []string) (result []string, err error) {
	err = r.db.View(func(txn *badger.Txn) error {
		for _, key := range keys {
			x, err := txn.Get([]byte(key))
			if err != nil {
				return err
			}
			err = x.Value(func(val []byte) error {
				result = append(result, string(val))
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if errors.Is(err, badger.ErrKeyNotFound) {
		return nil, ErrKeyNotFound
	}
	return
}

func (r *kv) GetKeyTTL(keyName string) (ttl int64, err error) {
	err = r.db.View(func(txn *badger.Txn) error {
		x, err := txn.Get([]byte(keyName))
		if err != nil {
			return err
		}
		if x.IsDeletedOrExpired() {
			ttl = -1
			return nil
		}
		exp := x.ExpiresAt()
		if exp == 0 {
			ttl = -1
			return nil
		}
		end := toTime(exp)
		ttl = int64(end.Sub(time.Now()).Seconds())
		return nil
	})
	if errors.Is(err, badger.ErrKeyNotFound) {
		return -2, ErrKeyNotFound
	}
	return
}

func toTime(ts uint64) time.Time {
	return time.Unix(int64(ts), 0)
}

func (r *kv) GetRawKey(keyName string) (string, error) {
	value, err := r.get(keyName)
	if err != nil {
		log.Debug("Error trying to get value:", err)
		return "", ErrKeyNotFound
	}
	return string(value), nil
}

func (r *kv) GetExp(keyName string) (exp int64, err error) {
	return r.GetKeyTTL(keyName)
}

func (r *kv) SetExp(keyName string, timeout int64) error {
	keyName = r.FixKey(keyName)
	return r.db.View(func(txn *badger.Txn) error {
		x, err := txn.Get([]byte(keyName))
		if err != nil {
			return err
		}
		v, err := x.ValueCopy(nil)
		if err != nil {
			return err
		}
		e := badger.NewEntry([]byte(keyName), v)
		e.WithTTL(time.Duration(timeout) * time.Second)
		return txn.SetEntry(e)
	})
}

// SetKey will create (or update) a key value in the store
func (r *kv) SetKey(keyName, session string, timeout int64) error {
	keyName = r.FixKey(keyName)
	return r.set(keyName, []byte(session), timeout)
}

func (r *kv) SetRawKey(keyName, session string, timeout int64) error {
	return r.set(keyName, []byte(session), timeout)
}

func (r *kv) updateNumber(key string, timeout int64, fn func(int64) int64) (v int64, err error) {
	err = r.db.Update(func(txn *badger.Txn) error {
		var v int64
		x, err := txn.Get([]byte(key))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				v = fn(v)
				value := strconv.FormatInt(v, 10)
				e := badger.NewEntry([]byte(key), []byte(value))
				if timeout != 0 {
					e.WithTTL(time.Duration(timeout) * time.Second)
				}
				return txn.SetEntry(e)
			}
			return err
		}
		err = x.Value(func(val []byte) error {
			v, err = strconv.ParseInt(string(val), 10, 64)
			return err
		})
		if err != nil {
			return err
		}
		v = fn(v)
		value := strconv.FormatInt(v, 10)
		e := badger.NewEntry([]byte(key), []byte(value))
		if timeout != 0 {
			e.WithTTL(time.Duration(timeout) * time.Second)
		}
		return txn.SetEntry(e)
	})
	return
}

// Decrement will decrement a key in redis
func (r *kv) Decrement(keyName string) {
	keyName = r.FixKey(keyName)
	_, err := r.updateNumber(keyName, 0, func(i int64) int64 { return i - 1 })
	if err != nil {
		log.Error("Error trying to decrement value:", err)
	}
}

// IncrementWithExpire will increment a key in redis
func (r *kv) IncrememntWithExpire(keyName string, expire int64) int64 {
	val, err := r.updateNumber(keyName, expire, func(i int64) int64 { return i + 1 })
	if err != nil {
		log.Error("Error trying to increment value:", err)
	} else {
		log.Debug("Incremented key: ", keyName, ", val is: ", val)
	}
	return val
}

// GetKeys will return all keys according to the filter (filter is a prefix - e.g. tyk.keys.*)
func (r *kv) GetKeys(filter string) (result []string) {
	err := r.iter(filter, func(txn *badger.Txn, item *badger.Item) error {
		result = append(result, r.CleanKey(string(item.Key())))
		return nil
	})
	if err != nil {
		log.Error("Error while fetching keys:", err)
		return nil
	}
	return
}

// GetKeysAndValuesWithFilter will return all keys and their values with a filter
func (r *kv) GetKeysAndValuesWithFilter(filter string) (result map[string]string) {
	result = make(map[string]string)
	err := r.iter(filter, func(txn *badger.Txn, item *badger.Item) error {
		return item.Value(func(val []byte) error {
			result[r.CleanKey(string(item.Key()))] = string(val)
			return nil
		})
	})
	if err != nil {
		log.Error("Error trying to get filtered client keys", err)
		return nil
	}
	return
}

// GetKeysAndValues will return all keys and their values - not to be used lightly
func (r *kv) GetKeysAndValues() map[string]string {
	return r.GetKeysAndValuesWithFilter("")
}

// DeleteKey will remove a key from the database
func (r *kv) DeleteKey(keyName string) bool {
	log.Debug("DEL Key was: ", keyName)
	log.Debug("DEL Key became: ", r.FixKey(keyName))
	keyName = r.FixKey(keyName)
	err := r.del(keyName)
	if err != nil {
		log.WithError(err).Error("Error trying to delete key")
	}
	return err == nil
}

// DeleteAllKeys will remove all keys from the database.
func (r *kv) DeleteAllKeys() bool {
	err := r.db.DropAll()
	if err != nil {
		log.WithError(err).Error("Error trying to delete keys")
	}
	return err == nil
}

// DeleteKey will remove a key from the database without prefixing, assumes user knows what they are doing
func (r *kv) DeleteRawKey(keyName string) bool {
	err := r.del(keyName)
	if err != nil {
		log.WithError(err).Error("Error trying to delete key")
		return false
	}
	return true
}

// DeleteKeys will remove a group of keys in bulk
func (r *kv) DeleteScanMatch(pattern string) bool {
	if pattern == "" || pattern == "x" {
		return r.DeleteAllKeys()
	}
	err := r.iter(pattern, func(txn *badger.Txn, item *badger.Item) error {
		return txn.Delete(item.KeyCopy(nil))
	})
	if err != nil {
		log.WithError(err).Error("Error trying to delete key")
		return false
	}
	return true
}

// DeleteKeys will remove a group of keys in bulk
func (r *kv) DeleteKeys(keys []string) bool {
	err := r.db.Update(func(txn *badger.Txn) error {
		for _, key := range keys {
			key = r.FixKey(key)
			if err := txn.Delete([]byte(key)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		log.WithError(err).Error("Error trying to delete keys", err)
		return false
	}
	return true
}

func (r *kv) Exists(key string) (bool, error) {
	key = r.FixKey(key)
	err := r.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		return nil
	})
	return !errors.Is(
		err, badger.ErrKeyNotFound,
	), err
}
