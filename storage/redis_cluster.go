package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	redis "github.com/go-redis/redis/v8"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage/internal"
)

// ErrRedisIsDown is returned when we can't communicate with redis.
var ErrRedisIsDown = errors.New("storage: Redis is either down or was not configured")

// RedisCluster is a storage manager that uses the redis database.
type RedisCluster struct {
	KeyPrefix   string
	HashKeys    bool
	IsCache     bool
	IsAnalytics bool

	// RedisController must be passed from the gateway
	RedisController *RedisController
}

func NewRedisClusterPool(isCache, isAnalytics bool, conf config.Config) StorageDriver {
	storageConfig := getStorageConfig(isCache, isAnalytics, conf)
	return internal.New(storageConfig)
}

func getRedisAddrs(config config.StorageOptionsConf) (addrs []string) {
	if len(config.Addrs) != 0 {
		addrs = config.Addrs
	} else {
		for h, p := range config.Hosts {
			addr := h + ":" + p
			addrs = append(addrs, addr)
		}
	}

	if len(addrs) == 0 && config.Port != 0 {
		addr := config.Host + ":" + strconv.Itoa(config.Port)
		addrs = append(addrs, addr)
	}

	return addrs
}

// Connect will establish a connection this is always true because we are
// dynamically using redis
func (r *RedisCluster) Connect() bool {
	return true
}

func (r *RedisCluster) singleton() StorageDriver {
	return r.RedisController.singleton(r.IsCache, r.IsAnalytics)
}

func (r *RedisCluster) check(err error, message string, opt ...interface{}) {
	isDebug := os.Getenv("TYK_LOGLEVEL") == "debug"

	// Turn on extra debug output with env
	if err != nil || isDebug {
		label := "RedisCluster." + message + ":"
		message := make([]interface{}, 0, 1+len(opt)*2)
		message = append(message, label)
		for _, o := range opt {
			message = append(message, " ")
			message = append(message, o)
		}
		log.WithError(err).Debug(message...)
	}
}

func (r *RedisCluster) hashKey(in string) string {
	if !r.HashKeys {
		// Not hashing? Return the raw key
		return in
	}

	return HashStr(in)
}

func (r *RedisCluster) prefixKey(keyName string) string {
	return r.KeyPrefix + r.hashKey(keyName)
}

func (r *RedisCluster) cleanKey(keyName string) string {
	return strings.Replace(keyName, r.KeyPrefix, "", 1)
}

func (r *RedisCluster) context() context.Context {
	return r.RedisController.Context()
}

func (r *RedisCluster) up() error {
	if !r.RedisController.Connected() {
		return ErrRedisIsDown
	}

	return nil
}

// GetKey will retrieve a key from the database
func (r *RedisCluster) GetKey(keyName string) (string, error) {
	val, err := r.GetRawKey(r.prefixKey(keyName))
	r.check(err, "GetKey", keyName)

	return val, err
}

// GetMultiKey gets multiple keys from the database
func (r *RedisCluster) GetMultiKey(keys []string) ([]string, error) {
	if err := r.up(); err != nil {
		return nil, err
	}

	driver := r.singleton()
	keyNames := make([]string, len(keys))
	copy(keyNames, keys)
	for index, val := range keyNames {
		keyNames[index] = r.prefixKey(val)
	}

	values, err := driver.MGet(r.context(), keyNames)
	r.check(err, "GetMultiKey", fromStringToInterfaceSlice(keys)...)

	result := make([]string, 0, len(values))

	ok := false
	for _, val := range values {
		strVal := fmt.Sprint(val)
		if strVal == "<nil>" {
			strVal = ""
		}
		ok = ok || strVal != ""
		result = append(result, strVal)
	}

	if !ok {
		return nil, ErrKeyNotFound
	}

	return result, nil
}

func (r *RedisCluster) GetRawKey(keyName string) (string, error) {
	if err := r.up(); err != nil {
		return "", err
	}

	value, err := r.singleton().Get(r.context(), keyName)
	r.check(err, "GetRawKey", keyName)

	if err != nil {
		return "", ErrKeyNotFound
	}

	return value, nil
}

func (r *RedisCluster) GetExp(keyName string) (int64, error) {
	if err := r.up(); err != nil {
		return 0, err
	}

	value, err := r.singleton().TTL(r.context(), r.prefixKey(keyName))
	r.check(err, "GetExp", keyName)

	if err != nil {
		return 0, ErrKeyNotFound
	}

	return value, nil
}

// Deprecated: Use GetExp()
func (r *RedisCluster) GetKeyTTL(keyName string) (int64, error) {
	return r.GetExp(keyName)
}

func (r *RedisCluster) SetExp(keyName string, timeout int64) error {
	if err := r.up(); err != nil {
		return err
	}

	keyName = r.prefixKey(keyName)
	err := r.singleton().Expire(r.context(), keyName, time.Duration(timeout)*time.Second)
	r.check(err, "SetExp", keyName, timeout)

	return err
}

// SetKey will create (or update) a key value in the store
func (r *RedisCluster) SetKey(keyName, value string, timeout int64) error {

	keyName = r.prefixKey(keyName)
	err := r.SetRawKey(keyName, value, timeout)
	r.check(err, "SetKey", keyName, value, timeout)

	return err
}

func (r *RedisCluster) SetRawKey(keyName, value string, timeout int64) error {
	if err := r.up(); err != nil {
		return err
	}

	err := r.singleton().Set(r.context(), keyName, value, time.Duration(timeout)*time.Second)
	r.check(err, "SetRawKey", keyName)

	return err
}

// Decrement will decrement a key in redis
func (r *RedisCluster) Decrement(keyName string) {
	if err := r.up(); err != nil {
		return
	}

	keyName = r.prefixKey(keyName)

	_, err := r.singleton().Decr(r.context(), keyName)
	r.check(err, "Decrement", keyName)
}

// IncrementWithExpire will increment a key in redis
func (r *RedisCluster) IncrementWithExpire(keyName string, expire int64) int64 {
	if err := r.up(); err != nil {
		return 0
	}

	cluster := r.singleton()

	// This function uses a raw key, so we shouldn't call prefixKey
	val, err := cluster.Incr(r.context(), keyName)
	r.check(err, "IncrementWithExpire (inc)", keyName, expire)

	if val == 1 && expire > 0 {
		err = cluster.Expire(r.context(), keyName, time.Duration(expire)*time.Second)
		r.check(err, "IncrementWithExpire (exp)", keyName, expire)
	}

	return val
}

// IncrememntWithExpire is deprecated, breaking api change
func (r *RedisCluster) IncrememntWithExpire(keyName string, expire int64) int64 {
	return r.IncrementWithExpire(keyName, expire)
}

// GetKeys will return all keys according to the filter (filter is a prefix - e.g. tyk.keys.*)
func (r *RedisCluster) GetKeys(filter string) []string {
	if err := r.up(); err != nil {
		return nil
	}

	filterHash := ""
	if filter != "" {
		filterHash = r.hashKey(filter)
	}
	searchStr := r.KeyPrefix + filterHash + "*"

	sessions, err := r.singleton().Keys(r.context(), searchStr)
	r.check(err, "GetKeys", filter)

	if err != nil {
		return nil
	}

	for i, v := range sessions {
		sessions[i] = r.cleanKey(v)
	}

	return sessions
}

// GetKeysAndValuesWithFilter will return all keys and their values with a filter
func (r *RedisCluster) GetKeysAndValuesWithFilter(filter string) map[string]string {
	if err := r.up(); err != nil {
		return nil
	}

	searchStr := r.KeyPrefix + filter

	client := r.singleton()
	values, err := client.GetKeysAndValuesWithFilter(r.context(), searchStr)
	r.check(err, "GetKeysAndValuesWithFilter", filter)
	if err != nil || len(values) == 0 {
		return nil
	}

	m := make(map[string]string)
	for k, v := range values {
		m[r.cleanKey(k)] = fmt.Sprint(v)
	}

	return m
}

// GetKeysAndValues will return all keys and their values - not to be used lightly
func (r *RedisCluster) GetKeysAndValues() map[string]string {
	return r.GetKeysAndValuesWithFilter("")
}

// DeleteKey will remove a key from the database
func (r *RedisCluster) DeleteKey(keyName string) bool {
	return r.DeleteRawKey(r.prefixKey(keyName))
}

// DeleteAllKeys will remove all keys from the database.
func (r *RedisCluster) DeleteAllKeys() bool {
	if err := r.up(); err != nil {
		return false
	}

	n, err := r.singleton().FlushAll(r.context())
	r.check(err, "DeleteAllKeys")

	return n
}

// DeleteKey will remove a key from the database without prefixing
func (r *RedisCluster) DeleteRawKey(keyName string) bool {
	if err := r.up(); err != nil {
		return false
	}

	err := r.singleton().Del(r.context(), keyName)
	r.check(err, "DeleteRawKey", keyName)

	return err == nil
}

// DeleteKeys will remove a group of keys in bulk
func (r *RedisCluster) DeleteScanMatch(pattern string) bool {
	if err := r.up(); err != nil {
		return false
	}

	ctx := r.context()
	client := r.singleton()

	_, err := client.DeleteScanMatch(ctx, pattern)
	r.check(err, "DeleteScanMatch", pattern)

	return err == nil
}

// DeleteKeys will remove a group of keys in bulk
func (r *RedisCluster) DeleteKeys(keys []string) bool {
	if err := r.up(); err != nil {
		return false
	}

	ctx := r.context()
	client := r.singleton()

	_, err := client.DeleteKeys(ctx, keys)
	r.check(err, "DeleteKeys", fromStringToInterfaceSlice(keys)...)

	return err == nil
}

// StartPubSubHandler will listen for a signal and run the callback for
// every subscription and message event.
func (r *RedisCluster) StartPubSubHandler(ctx context.Context, channel string, callback func(interface{})) error {
	if err := r.up(); err != nil {
		return err
	}

	client := r.singleton()
	if client == nil {
		return errors.New("Redis connection failed")
	}

	pubsub := client.Subscribe(ctx, channel)
	defer pubsub.Close()

	for {
		if err := r.handleReceive(ctx, pubsub.Receive, callback); err != nil {
			return err
		}
	}
}

// handleReceive is split from pubsub inner loop to inject fake
// receive function for code coverage tests.
func (r *RedisCluster) handleReceive(ctx context.Context, receiveFn func(context.Context) (interface{}, error), callback func(interface{})) error {
	msg, err := receiveFn(ctx)
	return r.handleMessage(msg, err, callback)
}

func (r *RedisCluster) handleMessage(msg interface{}, err error, callback func(interface{})) error {
	if err == nil {
		if callback != nil {
			callback(msg)
		}
		return err
	}

	// This error occurs when we cancel the context for pubsub.
	// To enable handling the error, it is coalesced to ErrClosed.
	if strings.Contains(err.Error(), "use of closed network connection") {
		r.check(err, "handleMessage (pubsub CLOSED)")
		return redis.ErrClosed
	}

	r.check(err, "handleMessage (pubsub OTHER)")

	return err
}

func (r *RedisCluster) Publish(channel, message string) error {
	if err := r.up(); err != nil {
		return err
	}

	_, err := r.singleton().Publish(r.context(), channel, message)
	r.check(err, "Publish", channel, message)

	return err
}

func (r *RedisCluster) GetAndDeleteSet(keyName string) []interface{} {
	if err := r.up(); err != nil {
		return nil
	}

	fixedKey := r.prefixKey(keyName)
	client := r.singleton()
	values, err := client.LRangeAndDel(r.context(), fixedKey)
	r.check(err, "GetAndDeleteSet", fixedKey)

	if err != nil || len(values) == 0 {
		return nil
	}

	return fromStringToInterfaceSlice(values)
}

func (r *RedisCluster) AppendToSet(keyName, value string) {
	if err := r.up(); err != nil {
		return
	}

	fixedKey := r.prefixKey(keyName)
	err := r.singleton().RPush(r.context(), fixedKey, value)
	r.check(err, "AppendToSet", fixedKey, value)
}

// Exists check if keyName exists
func (r *RedisCluster) Exists(keyName string) (bool, error) {
	if err := r.up(); err != nil {
		return false, err
	}

	fixedKey := r.prefixKey(keyName)
	exists, err := r.singleton().Exists(r.context(), fixedKey)
	r.check(err, "Exists", fixedKey)
	if err != nil {
		return false, ErrKeyNotFound
	}

	return exists > 0, nil
}

// RemoveFromList delete an value from a list idetinfied with the keyName
func (r *RedisCluster) RemoveFromList(keyName, value string) error {
	fixedKey := r.prefixKey(keyName)
	_, err := r.singleton().LRem(r.context(), fixedKey, 0, value)
	r.check(err, "RemoveFromList", fixedKey, 0, value)

	return err
}

// GetListRange gets range of elements of list identified by keyName
func (r *RedisCluster) GetListRange(keyName string, from, to int64) ([]string, error) {
	fixedKey := r.prefixKey(keyName)
	elements, err := r.singleton().LRange(r.context(), fixedKey, from, to)
	r.check(err, "GetListRange", fixedKey, from, to)

	return elements, nil
}

func (r *RedisCluster) AppendToSetPipelined(key string, values [][]byte) {
	if len(values) == 0 {
		return
	}

	if err := r.up(); err != nil {
		return
	}

	fixedKey := r.prefixKey(key)
	err := r.singleton().RPushPipelined(r.context(), fixedKey, values...)
	r.check(err, "AppendToSetPipelined", fixedKey)
}

func (r *RedisCluster) GetSet(keyName string) (map[string]string, error) {
	if err := r.up(); err != nil {
		return nil, err
	}

	fixedKey := r.prefixKey(keyName)
	val, err := r.singleton().SMembers(r.context(), fixedKey)
	r.check(err, "GetSet", fixedKey)

	if err != nil || len(val) == 0 {
		return nil, err
	}

	result := make(map[string]string, len(val))
	for i, value := range val {
		result[strconv.Itoa(i)] = value
	}

	return result, nil
}

func (r *RedisCluster) AddToSet(keyName, value string) {
	if err := r.up(); err != nil {
		return
	}

	fixedKey := r.prefixKey(keyName)
	err := r.singleton().SAdd(r.context(), fixedKey, value)
	r.check(err, "AddToSet", fixedKey, value)
}

func (r *RedisCluster) RemoveFromSet(keyName, value string) {
	if err := r.up(); err != nil {
		return
	}

	fixedKey := r.prefixKey(keyName)
	err := r.singleton().SRem(r.context(), fixedKey, value)
	r.check(err, "RemoveFromSet", fixedKey, value)
}

func (r *RedisCluster) IsMemberOfSet(keyName, value string) bool {
	if err := r.up(); err != nil {
		return false
	}

	fixedKey := r.prefixKey(keyName)
	val, err := r.singleton().SIsMember(r.context(), fixedKey, value)
	r.check(err, "IsMemberOfSet", fixedKey, value)

	return err == nil && val
}

// SetRollingWindow will append to a sorted set in redis and extract a timed window of values
func (r *RedisCluster) SetRollingWindow(keyName string, per int64, valueOverride string, pipeline bool) (int, []interface{}) {
	if err := r.up(); err != nil {
		return 0, nil
	}

	ctx := r.context()
	client := r.singleton()

	values, err := client.SetRollingWindow(ctx, keyName, per, valueOverride, pipeline)
	r.check(err, "SetRollingWindow", keyName)

	if err != nil || len(values) == 0 {
		return 0, nil
	}

	return len(values), fromStringToInterfaceSlice(values)
}

func (r *RedisCluster) GetRollingWindow(keyName string, per int64, pipeline bool) (int, []interface{}) {
	if err := r.up(); err != nil {
		return 0, nil
	}

	values, err := r.singleton().GetRollingWindow(r.context(), keyName, per, pipeline)
	r.check(err, "GetRollingWindow", keyName)

	if err != nil || len(values) == 0 {
		return 0, nil
	}

	return len(values), fromStringToInterfaceSlice(values)
}

// GetPrefix returns storage key prefix
func (r *RedisCluster) GetKeyPrefix() string {
	return r.KeyPrefix
}

// AddToSortedSet adds value with given score to sorted set identified by keyName
func (r *RedisCluster) AddToSortedSet(keyName, value string, score float64) {
	if err := r.up(); err != nil {
		return
	}

	fixedKey := r.prefixKey(keyName)
	_, err := r.singleton().ZAdd(r.context(), fixedKey, value, score)
	r.check(err, "AddToSortedSet", keyName, value, score)
}

// GetSortedSetRange gets range of elements of sorted set identified by keyName
func (r *RedisCluster) GetSortedSetRange(keyName, scoreFrom, scoreTo string) ([]string, []float64, error) {
	if err := r.up(); err != nil {
		return nil, nil, err
	}

	fixedKey := r.prefixKey(keyName)
	values, err := r.singleton().ZRangeByScoreWithScores(r.context(), fixedKey, scoreFrom, scoreTo)
	r.check(err, "GetSortedSetRange", keyName, scoreFrom, scoreTo)

	if err != nil || len(values) == 0 {
		return nil, nil, err
	}

	return values.Members(), values.Scores(), nil
}

// RemoveSortedSetRange removes range of elements from sorted set identified by keyName
func (r *RedisCluster) RemoveSortedSetRange(keyName, scoreFrom, scoreTo string) error {
	if err := r.up(); err != nil {
		return err
	}

	fixedKey := r.prefixKey(keyName)
	_, err := r.singleton().ZRemRangeByScore(r.context(), fixedKey, scoreFrom, scoreTo)
	r.check(err, "RemoveSortedSetRange", fixedKey, scoreFrom, scoreTo)

	return err
}

func (r *RedisCluster) ControllerInitiated() bool {
	return r.RedisController != nil
}
