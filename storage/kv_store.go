package storage

import (
	"sync"
	"time"

	"github.com/dgraph-io/badger/v2"
	"gopkg.in/fatih/set.v0"
)

var _ KV = (*KVStore)(nil)

type KVStore struct {
	db        *badger.DB
	KeyPrefix string
	HashKeys  bool
	sets      *sync.Map
}

func (kv *KVStore) fixKey(key string) string {
	if kv.KeyPrefix == "" && !kv.HashKeys {
		return key
	}
	return kv.KeyPrefix + kv.hashKey(key)
}

func (kv *KVStore) hashKey(key string) string {
	if key == "" {
		return key
	}
	if !kv.HashKeys {
		return key
	}
	return HashStr(key)
}

func NewKVStore(dir string) (*KVStore, error) {
	opts := badger.DefaultOptions(dir)
	if dir == "" {
		// We still use badger but in memory now
		opts.InMemory = true
	}
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return &KVStore{db: db, sets: new(sync.Map)}, nil
}

func (kv *KVStore) SetKey(key, value string, timeout int64) error {
	return kv.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(kv.fixKey(key)), []byte(value))
	})
}

func (kv *KVStore) GetKey(key string) (value string, err error) {
	err = kv.db.View(func(txn *badger.Txn) error {
		it, ierr := txn.Get([]byte(kv.fixKey(key)))
		if ierr != nil {
			return ierr
		}
		return it.Value(func(val []byte) error {
			value = string(val)
			return nil
		})
	})
	return
}

func (kv *KVStore) GetKeys(pattern string) (keys []string) {
	prefix := kv.patternToPrefix(pattern)
	kv.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			keys = append(keys, string(item.Key()))
		}
		return nil
	})
	return
}

func (kv *KVStore) DeleteKey(key string) bool {
	return kv.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(kv.fixKey(key)))
	}) == nil
}

func (kv *KVStore) patternToPrefix(pattern string) []byte {
	if pattern == "*" {
		pattern = ""
	} else if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		pattern = pattern[:len(pattern)-1]
	}
	return []byte(kv.fixKey(pattern))
}

func (kv *KVStore) DeleteScanMatch(pattern string) bool {
	prefix := kv.patternToPrefix(pattern)
	var keys []string
	kv.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			keys = append(keys, string(item.Key()))
		}
		return nil
	})
	if keys == nil {
		return true
	}
	return kv.db.Update(func(txn *badger.Txn) error {
		for _, v := range keys {
			if err := txn.Delete([]byte(v)); err != nil {
				return err
			}
		}
		return nil
	}) == nil
}

func (kv *KVStore) Close() error {
	return kv.db.Close()
}

func (kv *KVStore) SetExp(key string, exp int64) error {
	return kv.db.Update(func(txn *badger.Txn) error {
		i, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		v := make([]byte, i.ValueSize())
		i.ValueCopy(v)
		e := badger.NewEntry([]byte(key), v)
		return txn.SetEntry(e.WithTTL(time.Duration(exp) * time.Second))
	})
}

func (kv *KVStore) GetExp(key string) (exp int64, err error) {
	err = kv.db.View(func(txn *badger.Txn) error {
		e, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		exp = int64(e.ExpiresAt())
		return nil
	})
	return
}

func (kv *KVStore) DeleteAllKeys() error {
	return kv.db.DropAll()
}

func (kv *KVStore) GetKeyPrefix() string {
	return kv.KeyPrefix
}

func (kv *KVStore) AddToSet(key, value string) {
	key = kv.fixKey(key)
	if s, ok := kv.sets.Load(key); ok {
		ss := s.(*set.Set)
		ss.Add(value)
	} else {
		ss := new(set.Set)
		ss.Add(value)
		kv.sets.Store(key, ss)
	}

}
