package storage

import (
	"github.com/dgraph-io/badger/v3"
)

var simple nativeDB

type nativeDB struct {
	// rate stores rate limiting data. We rely on versions to achieve
	// rolling window implementation. This requires us to keep lots of versions of
	// the same key, we don't need this for other uses so we manage this
	// differently
	rate *badger.DB

	general *badger.DB
}

var _ Handler = (*Native)(nil)

type Native struct {
	Options

	nativeNotify
	nativeAnalytics
}

func (n Native) Connect() bool {
	return true
}

func (n Native) SetRollingWindow(key string, per int64, val string, pipeline bool) (int, []interface{}) {
	return (&rate{db: simple.rate}).SetRollingWindow(key, per, val, pipeline)
}

func (n Native) GetRollingWindow(key string, per int64, pipeline bool) (int, []interface{}) {
	return (&rate{db: simple.rate}).GetRollingWindow(key, per, pipeline)
}

func (n Native) GetKey(key string) (string, error) {
	return (&kv{Options: n.Options, db: simple.general}).GetKey(key)
}
func (n Native) GetMultiKey(keys []string) ([]string, error) {
	return (&kv{Options: n.Options, db: simple.general}).GetMultiKey(keys)
}
func (n Native) GetRawKey(key string) (string, error) {
	return (&kv{Options: n.Options, db: simple.general}).GetRawKey(key)
}

func (n Native) SetKey(key string, session string, timeout int64) error {
	return (&kv{Options: n.Options, db: simple.general}).SetKey(key, session, timeout)
}

func (n Native) SetRawKey(key string, session string, timeout int64) error {
	return (&kv{Options: n.Options, db: simple.general}).SetRawKey(key, session, timeout)
}

func (n Native) GetKeys(filter string) []string {
	return (&kv{Options: n.Options, db: simple.general}).GetKeys(filter)
}

func (n Native) DeleteKey(filter string) bool {
	return (&kv{Options: n.Options, db: simple.general}).DeleteKey(filter)
}

func (n Native) DeleteAllKeys() bool {
	return (&kv{Options: n.Options, db: simple.general}).DeleteAllKeys()
}

func (n Native) DeleteRawKey(key string) bool {
	return (&kv{Options: n.Options, db: simple.general}).DeleteRawKey(key)
}
func (n Native) GetKeysAndValues() map[string]string {
	return (&kv{Options: n.Options, db: simple.general}).GetKeysAndValues()
}
func (n Native) GetKeysAndValuesWithFilter(filter string) map[string]string {
	return (&kv{Options: n.Options, db: simple.general}).GetKeysAndValuesWithFilter(filter)
}
func (n Native) DeleteKeys(keys []string) bool {
	return (&kv{Options: n.Options, db: simple.general}).DeleteKeys(keys)
}
func (n Native) Decrement(key string) {
	(&kv{Options: n.Options, db: simple.general}).Decrement(key)
}
func (n Native) IncrememntWithExpire(key string, expire int64) int64 {
	return (&kv{Options: n.Options, db: simple.general}).IncrememntWithExpire(key, expire)
}

func (n Native) DeleteScanMatch(filter string) bool {
	return (&kv{Options: n.Options, db: simple.general}).DeleteScanMatch(filter)
}

func (n Native) GetKeyPrefix() string {
	return n.KeyPrefix
}

func (n Native) Exists(key string) (bool, error) {
	return (&kv{Options: n.Options, db: simple.general}).Exists(key)
}

func (n Native) GetKeyTTL(key string) (ttl int64, err error) {
	return (&kv{Options: n.Options, db: simple.general}).GetKeyTTL(key)
}

func (n Native) AddToSet(key string, value string) {
	(&nativeRedis{Options: n.Options, db: simple.general}).AddToSet(key, value)
}

func (n Native) GetSet(key string) (map[string]string, error) {
	return (&nativeRedis{Options: n.Options, db: simple.general}).GetSet(key)
}

func (n Native) AddToSortedSet(key string, value string, score float64) {
	(&nativeRedis{Options: n.Options, db: simple.general}).AddToSortedSet(key, value, score)
}

func (n Native) RemoveFromSet(key string, value string) {
	(&nativeRedis{Options: n.Options, db: simple.general}).RemoveFromSet(key, value)
}

func (n Native) GetSortedSetRange(key string, from string, to string) ([]string, []float64, error) {
	return (&nativeRedis{Options: n.Options, db: simple.general}).GetSortedSetRange(key, from, to)
}

func (n Native) RemoveSortedSetRange(key string, from string, to string) error {
	return (&nativeRedis{Options: n.Options, db: simple.general}).RemoveSortedSetRange(key, from, to)
}

func (n Native) GetListRange(key string, from int64, to int64) ([]string, error) {
	return (&nativeRedis{Options: n.Options, db: simple.general}).GetListRange(key, from, to)
}

func (n Native) RemoveFromList(key string, value string) error {
	return (&nativeRedis{Options: n.Options, db: simple.general}).RemoveFromList(key, value)
}

func (n Native) AppendToSet(key string, value string) {
	(&nativeRedis{Options: n.Options, db: simple.general}).AppendToSet(key, value)
}
