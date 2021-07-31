package storage

import (
	"bytes"
	"encoding/gob"
	"errors"
	"sort"
	"strconv"

	"github.com/dgraph-io/badger/v3"
)

type Set map[string]float64

func (s Set) Insert(value string, score float64) {
	s[value] = score
}

func (s Set) Delete(value string) {
	delete(s, value)
}

func (s Set) Append(value string, score float64) {
	s[value] = score
}

type scoreItem struct {
	value string
	score float64
}

func (s Set) DeleteFilter(filer func(score float64) bool) {
	for k, v := range s {
		if filer(v) {
			delete(s, k)
		}
	}
}

func (s Set) List(filer func(score float64) bool) (it []*scoreItem) {
	for k, v := range s {
		if filer(v) {
			it = append(it, &scoreItem{
				value: k, score: v,
			})
		}
	}
	sort.Slice(it, func(i, j int) bool {
		return it[0].score < it[j].score
	})
	return
}

var _ Redis = (*nativeRedis)(nil)

type nativeRedis struct {
	Options
	db *badger.DB
}

func (r *nativeRedis) update(key string, fn func(set Set) error) error {
	return r.db.Update(func(txn *badger.Txn) error {
		it, err := txn.Get([]byte(key))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				s := make(Set)
				if err := fn(s); err != nil {
					return err
				}
				var buf bytes.Buffer
				if err := gob.NewEncoder(&buf).Encode(s); err != nil {
					return err
				}
				return txn.Set([]byte(key), buf.Bytes())
			}
			return err
		}
		var s Set
		err = it.Value(func(val []byte) error {
			return gob.NewDecoder(bytes.NewReader(val)).Decode(&s)
		})
		if err != nil {
			return err
		}
		if err := fn(s); err != nil {
			return err
		}
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(s); err != nil {
			return err
		}
		return txn.Set([]byte(key), buf.Bytes())
	})
}
func (r *nativeRedis) view(key string, fn func(set Set) error) error {
	return r.db.View(func(txn *badger.Txn) error {
		it, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		var s Set
		err = it.Value(func(val []byte) error {
			return gob.NewDecoder(bytes.NewReader(val)).Decode(&s)
		})
		if err != nil {
			return err
		}
		return fn(s)
	})
}

func (r *nativeRedis) AddToSet(key string, value string) {
	key = r.FixKey(key)
	r.update(key, func(set Set) error {
		set.Insert(value, 0)
		return nil
	})
}

func (r *nativeRedis) GetSet(key string) (result map[string]string, err error) {
	key = r.FixKey(key)
	err = r.view(key, func(set Set) error {
		result = make(map[string]string)
		for i, value := range set.List(func(score float64) bool { return true }) {
			result[strconv.Itoa(i)] = value.value
		}
		return nil
	})
	return
}

func (r *nativeRedis) GetListRange(key string, from int64, to int64) (result []string, err error) {
	key = r.FixKey(key)
	err = r.view(key, func(set Set) error {
		for _, value := range set.List(func(score float64) bool { return true }) {
			result = append(result, value.value)
		}
		return nil
	})
	return
}

func (r *nativeRedis) AddToSortedSet(key string, value string, score float64) {
	key = r.FixKey(key)
	r.update(key, func(set Set) error {
		set.Append(value, score)
		return nil
	})
}

func (r *nativeRedis) RemoveFromSet(key string, value string) {
	key = r.FixKey(key)
	r.update(key, func(set Set) error {
		set.Delete(value)
		return nil
	})
}

func (r *nativeRedis) RemoveFromList(key string, value string) error {
	key = r.FixKey(key)
	return r.update(key, func(set Set) error {
		set.Delete(value)
		return nil
	})
}

func (r *nativeRedis) AppendToSet(key string, value string) {
	key = r.FixKey(key)
	r.update(key, func(set Set) error {
		set.Append(value, -1)
		return nil
	})
}

func (r *nativeRedis) AppendToSetPipelined(key string, value string) {
	key = r.FixKey(key)
	r.update(key, func(set Set) error {
		set.Append(value, -1)
		return nil
	})
}

func (r *nativeRedis) GetSortedSetRange(key string, from string, to string) (result []string, scores []float64, err error) {
	a, _ := strconv.ParseFloat(from, 64)
	b, _ := strconv.ParseFloat(to, 64)
	key = r.FixKey(key)
	err = r.view(key, func(set Set) error {
		for _, value := range set.List(func(score float64) bool { return a <= score && score <= b }) {
			result = append(result, value.value)
			scores = append(scores, value.score)
		}
		return nil
	})
	return
}

func (r *nativeRedis) RemoveSortedSetRange(key string, from string, to string) error {
	a, _ := strconv.ParseFloat(from, 64)
	b, _ := strconv.ParseFloat(to, 64)
	key = r.FixKey(key)
	return r.update(key, func(set Set) error {
		set.DeleteFilter(func(score float64) bool {
			return a <= score && score <= b
		})
		return nil
	})
}
