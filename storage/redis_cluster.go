package storage

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	tempflusher "github.com/TykTechnologies/storage/temporal/flusher"
	tempkv "github.com/TykTechnologies/storage/temporal/keyvalue"
	templist "github.com/TykTechnologies/storage/temporal/list"
	"github.com/TykTechnologies/storage/temporal/model"
	tempqueue "github.com/TykTechnologies/storage/temporal/queue"

	//nolint:misspell
	tempset "github.com/TykTechnologies/storage/temporal/set"
	tempsortedset "github.com/TykTechnologies/storage/temporal/sortedset"
	redis "github.com/TykTechnologies/tyk/internal/redis"

	"github.com/TykTechnologies/tyk/config"
)

var (
	// ErrRedisIsDown is returned when we can't communicate with redis
	ErrRedisIsDown = errors.New("storage: Redis is either down or was not configured")

	// ErrStorageConn is returned when we can't get a connection from the ConnectionHandler
	ErrStorageConn = fmt.Errorf("Error trying to get singleton instance: %w", ErrRedisIsDown)
)

// RedisCluster is a storage manager that uses the redis database.
type RedisCluster struct {
	KeyPrefix   string
	HashKeys    bool
	IsCache     bool
	IsAnalytics bool

	ConnectionHandler *ConnectionHandler
	// RedisController must remain for compatibility with goplugins
	RedisController *RedisController

	storageMu        sync.Mutex
	kvStorage        model.KeyValue
	flusherStorage   model.Flusher
	queueStorage     model.Queue
	listStorage      model.List
	setStorage       model.Set
	sortedSetStorage model.SortedSet
}

func (r *RedisCluster) getConnectionHandler() *ConnectionHandler {
	if r.RedisController != nil {
		return r.RedisController.connection
	}
	return r.ConnectionHandler
}

func getRedisAddrs(conf config.StorageOptionsConf) (addrs []string) {
	return conf.HostAddrs()
}

// Connect will establish a connection this is always true because we are
// dynamically using redis
func (r *RedisCluster) Connect() bool {
	return r.getConnectionHandler().Connected()
}

// Client will return a redis v8 RedisClient. This function allows
// implementation using the old storage clients.
func (r *RedisCluster) Client() (redis.UniversalClient, error) {
	if err := r.up(); err != nil {
		return nil, err
	}

	conn := r.getConnectionHandler().getConnection(r.IsCache, r.IsAnalytics)
	if conn == nil {
		return nil, ErrStorageConn
	}

	var client redis.UniversalClient

	if ok := conn.As(&client); !ok {
		return nil, errors.New("error converting connection to redis client")
	}

	return client, nil
}

func (r *RedisCluster) kv() (model.KeyValue, error) {
	if err := r.up(); err != nil {
		return nil, err
	}

	r.storageMu.Lock()
	defer r.storageMu.Unlock()

	if r.kvStorage != nil {
		return r.kvStorage, nil
	}

	conn := r.getConnectionHandler().getConnection(r.IsCache, r.IsAnalytics)
	if conn == nil {
		return nil, ErrStorageConn
	}

	kvStorage, err := tempkv.NewKeyValue(conn)
	if err != nil {
		return nil, err
	}
	r.kvStorage = kvStorage

	return kvStorage, nil
}

func (r *RedisCluster) flusher() (model.Flusher, error) {
	if err := r.up(); err != nil {
		return nil, err
	}

	r.storageMu.Lock()
	defer r.storageMu.Unlock()
	if r.flusherStorage != nil {
		return r.flusherStorage, nil
	}

	conn := r.getConnectionHandler().getConnection(r.IsCache, r.IsAnalytics)
	if conn == nil {
		return nil, ErrStorageConn
	}

	flusherStorage, err := tempflusher.NewFlusher(conn)
	if err != nil {
		return nil, err
	}
	r.flusherStorage = flusherStorage

	return flusherStorage, nil
}

func (r *RedisCluster) queue() (model.Queue, error) {
	if err := r.up(); err != nil {
		return nil, err
	}

	r.storageMu.Lock()
	defer r.storageMu.Unlock()

	if r.queueStorage != nil {
		return r.queueStorage, nil
	}

	conn := r.getConnectionHandler().getConnection(r.IsCache, r.IsAnalytics)
	if conn == nil {
		return nil, ErrStorageConn
	}

	queueStorage, err := tempqueue.NewQueue(conn)
	if err != nil {
		return nil, err
	}
	r.queueStorage = queueStorage

	return queueStorage, nil
}

func (r *RedisCluster) list() (model.List, error) {
	if err := r.up(); err != nil {
		return nil, err
	}

	r.storageMu.Lock()
	defer r.storageMu.Unlock()
	if r.listStorage != nil {
		return r.listStorage, nil
	}

	conn := r.getConnectionHandler().getConnection(r.IsCache, r.IsAnalytics)
	if conn == nil {
		return nil, ErrStorageConn
	}

	listStorage, err := templist.NewList(conn)
	if err != nil {
		return nil, err
	}
	r.listStorage = listStorage

	return listStorage, nil
}

func (r *RedisCluster) set() (model.Set, error) {
	if err := r.up(); err != nil {
		return nil, err
	}
	r.storageMu.Lock()
	defer r.storageMu.Unlock()
	if r.setStorage != nil {
		return r.setStorage, nil
	}

	conn := r.getConnectionHandler().getConnection(r.IsCache, r.IsAnalytics)
	if conn == nil {
		return nil, ErrStorageConn
	}

	setStorage, err := tempset.NewSet(conn)
	if err != nil {
		return nil, err
	}
	r.setStorage = setStorage

	return setStorage, nil
}

func (r *RedisCluster) sortedSet() (model.SortedSet, error) {
	if err := r.up(); err != nil {
		return nil, err
	}
	r.storageMu.Lock()
	defer r.storageMu.Unlock()
	if r.sortedSetStorage != nil {
		return r.sortedSetStorage, nil
	}

	conn := r.getConnectionHandler().getConnection(r.IsCache, r.IsAnalytics)
	if conn == nil {
		return nil, ErrStorageConn
	}

	sortedSetStorage, err := tempsortedset.NewSortedSet(conn)
	if err != nil {
		return nil, err
	}
	r.sortedSetStorage = sortedSetStorage

	return sortedSetStorage, nil
}

func (r *RedisCluster) hashKey(in string) string {
	if !r.HashKeys {
		// Not hashing? Return the raw key
		return in
	}
	return HashStr(in)
}

func (r *RedisCluster) fixKey(keyName string) string {
	return r.KeyPrefix + r.hashKey(keyName)
}

func (r *RedisCluster) cleanKey(keyName string) string {
	return strings.Replace(keyName, r.KeyPrefix, "", 1)
}

func (r *RedisCluster) up() error {
	if !r.getConnectionHandler().Connected() {
		return ErrRedisIsDown
	}
	return nil
}

// GetKey will retrieve a key from the database
func (r *RedisCluster) GetKey(keyName string) (string, error) {
	storage, err := r.kv()
	if err != nil {
		log.Error(err)
		return "", err
	}

	value, err := storage.Get(context.Background(), r.fixKey(keyName))
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			log.Debug("Error trying to get value:", err)
		}
		return "", ErrKeyNotFound
	}

	return value, nil
}

// GetMultiKey gets multiple keys from the database
func (r *RedisCluster) GetMultiKey(keys []string) ([]string, error) {
	storage, err := r.kv()
	if err != nil {
		log.Error(err)
		return nil, err
	}

	keyNames := make([]string, len(keys))
	copy(keyNames, keys)
	for index, val := range keyNames {
		keyNames[index] = r.fixKey(val)
	}

	values, err := storage.GetMulti(context.Background(), keyNames)
	if err != nil {
		log.WithError(err).Debug("Error trying to get value")
		return nil, ErrKeyNotFound
	}
	result := make([]string, 0)
	for _, val := range values {
		strVal := fmt.Sprint(val)
		if strVal == "<nil>" {
			strVal = ""
		}
		result = append(result, strVal)
	}

	for _, val := range result {
		if val != "" {
			return result, nil
		}
	}

	return nil, ErrKeyNotFound
}

// GetRawMultiKey retrieves multiple values using a Pipeline.
func (r *RedisCluster) GetRawMultiKey(keys []string) ([]string, error) {
	client, err := r.Client()
	if err != nil {
		return nil, err
	}

	if clusterClient, ok := client.(*redis.ClusterClient); ok {
		return r.pipelineFetch(clusterClient, keys)
	}

	cmd := client.MGet(context.Background(), keys...)
	vals, err := cmd.Result()
	if err != nil {
		return nil, err
	}

	// Convert []interface{} to []string
	result := make([]string, len(vals))
	for i, v := range vals {
		if v == nil {
			result[i] = ""
		} else {
			result[i] = fmt.Sprint(v)
		}
	}

	return result, nil
}

// pipelineFetch executes the batch using a Redis Pipeline.
func (r *RedisCluster) pipelineFetch(client *redis.ClusterClient, keys []string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pipe := client.Pipeline()

	cmds := make([]*redis.StringCmd, len(keys))
	for i, key := range keys {
		cmds[i] = pipe.Get(ctx, key)
	}

	_, err := pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, err
	}

	result := make([]string, len(keys))
	for i, cmd := range cmds {
		val, err := cmd.Result()
		if errors.Is(err, redis.Nil) {
			result[i] = ""
		} else if err != nil {
			return nil, err
		} else {
			result[i] = val
		}
	}

	return result, nil
}

func (r *RedisCluster) GetKeyTTL(keyName string) (ttl int64, err error) {
	storage, err := r.kv()
	if err != nil {
		log.Error(err)
		return 0, err
	}

	return storage.TTL(context.Background(), r.fixKey(keyName))
}

func (r *RedisCluster) GetRawKey(keyName string) (string, error) {
	storage, err := r.kv()
	if err != nil {
		log.Error(err)
		return "", err
	}

	value, err := storage.Get(context.Background(), keyName)
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			log.Debug("Error trying to get value:", err)
		}
		return "", ErrKeyNotFound
	}

	return value, nil
}

func (r *RedisCluster) GetExp(keyName string) (int64, error) {
	return r.GetKeyTTL(keyName)
}

func (r *RedisCluster) SetExp(keyName string, timeout int64) error {
	storage, err := r.kv()
	if err != nil {
		log.Error(err)
		return err
	}

	return storage.Expire(context.Background(), r.fixKey(keyName), time.Duration(timeout)*time.Second)
}

// SetKey will create (or update) a key value in the store
func (r *RedisCluster) SetKey(keyName, session string, timeout int64) error {
	return r.SetRawKey(r.fixKey(keyName), session, timeout)
}

func (r *RedisCluster) SetRawKey(keyName, session string, timeout int64) error {
	storage, err := r.kv()
	if err != nil {
		log.Error(err)
		return err
	}

	return storage.Set(context.Background(), keyName, session, time.Duration(timeout)*time.Second)
}

// Lock implements a distributed lock in a cluster.
func (r *RedisCluster) Lock(key string, timeout time.Duration) (bool, error) {
	storage, err := r.kv()
	if err != nil {
		log.Error(err)
		return false, err
	}

	set, err := storage.SetIfNotExist(context.Background(), key, "1", timeout)
	if err != nil {
		log.WithError(err).Error("Error trying to set value")
		return false, err
	}
	return set, nil
}

// Decrement will decrement a key in redis
func (r *RedisCluster) Decrement(keyName string) {
	keyName = r.fixKey(keyName)
	// log.Debug("Decrementing key: ", keyName)
	storage, err := r.kv()
	if err != nil {
		log.Error(err)
		return
	}

	_, err = storage.Decrement(context.Background(), keyName)
	if err != nil {
		log.Error("Error trying to decrement value:", err)
	}
}

// IncrementWithExpire will increment a key in redis
func (r *RedisCluster) IncrememntWithExpire(keyName string, expire int64) int64 {
	storage, err := r.kv()
	if err != nil {
		log.Error(err)
		return 0
	}

	// This function uses a raw key, so we shouldn't call fixKey
	fixedKey := keyName

	val, err := storage.Increment(context.Background(), fixedKey)
	if err != nil {
		log.Error("Error trying to increment value:", err)
	} else {
		log.Debug("Incremented key: ", fixedKey, ", val is: ", val)
	}

	if val == 1 && expire > 0 {
		log.Debug("--> Setting Expire")
		err = storage.Expire(context.Background(), fixedKey, time.Duration(expire)*time.Second)
		if err != nil {
			log.Error("Error trying to set expire on key:", err)
		}
	}

	return val
}

// GetKeys will return all keys according to the filter (filter is a prefix - e.g. tyk.keys.*)
func (r *RedisCluster) GetKeys(filter string) []string {
	filterHash := ""
	if filter != "" {
		filterHash = r.hashKey(filter)
	}

	searchStr := r.KeyPrefix + filterHash + "*"
	log.Debug("[STORE] Getting list by: ", searchStr)

	sessions, err := r.ScanKeys(searchStr)
	if err != nil {
		log.Error("Error while fetching keys:", err)
		return nil
	}

	for i, v := range sessions {
		sessions[i] = r.cleanKey(v)
	}

	return sessions
}

// GetKeysAndValuesWithFilter will return all keys and their values with a filter
func (r *RedisCluster) GetKeysAndValuesWithFilter(filter string) map[string]string {
	storage, err := r.kv()
	if err != nil {
		log.Error(err)
		return nil
	}

	if filter != "" && !strings.Contains(filter, r.KeyPrefix) {
		filter = r.KeyPrefix + filter
	}

	keysAndValues, err := storage.GetKeysAndValuesWithFilter(context.Background(), filter)
	if err != nil {
		log.Error("Error trying to get client keys: ", err)
		return nil
	}

	m := make(map[string]string)
	for key, value := range keysAndValues {
		m[r.cleanKey(key)] = fmt.Sprint(value)
	}

	return m
}

// GetKeysAndValues will return all keys and their values - not to be used lightly
func (r *RedisCluster) GetKeysAndValues() map[string]string {
	return r.GetKeysAndValuesWithFilter("")
}

// DeleteKey will remove a key from the database
func (r *RedisCluster) DeleteKey(keyName string) bool {
	storage, err := r.kv()
	if err != nil {
		log.Error(err)
		return false
	}

	exist, err := storage.Exists(context.Background(), r.fixKey(keyName))
	if err != nil || !exist {
		return false
	}

	err = storage.Delete(context.Background(), r.fixKey(keyName))
	if err != nil {
		log.WithError(err).Error("Error trying to delete key")
		return false
	}

	return true
}

// DeleteAllKeys will remove all keys from the database.
func (r *RedisCluster) DeleteAllKeys() bool {
	storage, err := r.flusher()
	if err != nil {
		log.Error(err)
		return false
	}

	err = storage.FlushAll(context.Background())
	if err != nil {
		log.WithError(err).Error("Error trying to delete keys")
		return false
	}

	return true
}

// DeleteKey will remove a key from the database without prefixing, assumes user knows what they are doing
func (r *RedisCluster) DeleteRawKey(keyName string) bool {
	storage, err := r.kv()
	if err != nil {
		log.Error(err)
		return false
	}

	err = storage.Delete(context.Background(), keyName)
	if err != nil {
		log.WithError(err).Error("Error trying to delete raw key")
		return false
	}
	return true
}

// DeleteKeys will remove a group of keys in bulk
func (r *RedisCluster) DeleteScanMatch(pattern string) bool {
	storage, err := r.kv()
	if err != nil {
		log.Error(err)
		return false
	}
	log.Debug("Deleting: ", pattern)

	_, err = storage.DeleteScanMatch(context.Background(), pattern)
	if err != nil {
		log.WithError(err).Error("Error trying to delete key pattern ", pattern)
		return false
	}
	return true
}

func (r *RedisCluster) DeleteRawKeys(keys []string) bool {
	storage, err := r.kv()
	if err != nil {
		log.Error(err)
		return false
	}

	deleted, err := storage.DeleteKeys(context.Background(), keys)
	if err != nil {
		log.WithError(err).Error("Error trying to delete keys ")
		return false
	}
	return deleted > 0
}

// DeleteKeys will remove a group of keys in bulk
func (r *RedisCluster) DeleteKeys(keys []string) bool {
	storage, err := r.kv()
	if err != nil {
		log.Error(err)
		return false
	}

	for i, v := range keys {
		keys[i] = r.fixKey(v)
	}

	deleted, err := storage.DeleteKeys(context.Background(), keys)
	if err != nil {
		log.WithError(err).Error("Error trying to delete keys ")
		return false
	}
	return deleted > 0
}

// StartPubSubHandler will listen for a signal and run the callback for
// every subscription and message event.
func (r *RedisCluster) StartPubSubHandler(ctx context.Context, channel string, callback func(interface{})) error {
	storage, err := r.queue()
	if err != nil {
		log.Error(err)
		return err
	}

	pubsub := storage.Subscribe(ctx, channel)
	defer pubsub.Close()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			if err := r.handleReceive(ctx, pubsub.Receive, callback); err != nil {
				return err
			}
		}
	}
}

// handleReceive is split from pubsub inner loop to inject fake
// receive function for code coverage tests.
func (r *RedisCluster) handleReceive(ctx context.Context, receiveFn func(context.Context) (model.Message, error), callback func(interface{})) error {
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

	log.Error("Error while receiving pubsub message:", err)

	// This error occurs when we cancel the context for pubsub.
	// To enable handling the error, it is coalesced to ErrClosed.
	if strings.Contains(err.Error(), "use of closed network connection") {
		return redis.ErrClosed
	}

	return err
}

func (r *RedisCluster) Publish(channel, message string) error {
	storage, err := r.queue()
	if err != nil {
		log.Error(err)
		return err
	}

	_, err = storage.Publish(context.Background(), channel, message)
	if err != nil {
		log.Error("Error trying to publish message: ", err)
		return err
	}
	return nil
}

func (r *RedisCluster) GetAndDeleteSet(keyName string) []interface{} {
	storage, err := r.list()
	if err != nil {
		log.Error(err)
		return nil
	}

	log.Debug("Getting raw key set: ", keyName)
	log.Debug("keyName is: ", keyName)
	fixedKey := r.fixKey(keyName)
	log.Debug("Fixed keyname is: ", fixedKey)

	values, err := storage.Pop(context.Background(), fixedKey, -1)
	if err != nil {
		log.Error("Multi command failed: ", err)
		return nil
	}

	if len(values) == 0 {
		return []interface{}{}
	}

	result := make([]interface{}, len(values))
	for i, v := range values {
		result[i] = v
	}

	return result
}

func (r *RedisCluster) AppendToSet(keyName, value string) {
	fixedKey := r.fixKey(keyName)
	log.WithField("keyName", keyName).Debug("Pushing to raw key list")
	log.WithField("fixedKey", fixedKey).Debug("Appending to fixed key list")
	storage, err := r.list()
	if err != nil {
		log.Error(err)
		return
	}

	err = storage.Append(context.Background(), false, fixedKey, []byte(value))
	if err != nil {
		log.WithError(err).Error("Error trying to append to set keys")
	}
}

// Exists check if keyName exists
func (r *RedisCluster) Exists(keyName string) (bool, error) {
	fixedKey := r.fixKey(keyName)
	log.WithField("keyName", fixedKey).Debug("Checking if exists")

	storage, err := r.kv()
	if err != nil {
		log.Error(err)
		return false, err
	}

	exists, err := storage.Exists(context.Background(), fixedKey)
	if err != nil {
		log.Error("Error trying to check if key exists: ", err)
		return false, err
	}
	return exists, nil
}

// RemoveFromList delete an value from a list idetinfied with the keyName
func (r *RedisCluster) RemoveFromList(keyName, value string) error {
	fixedKey := r.fixKey(keyName)
	logEntry := logrus.Fields{
		"keyName":  keyName,
		"fixedKey": fixedKey,
		"value":    value,
	}
	log.WithFields(logEntry).Debug("Removing value from list")
	storage, err := r.list()
	if err != nil {
		log.Error(err)
		return err
	}

	_, err = storage.Remove(context.Background(), fixedKey, 0, value)
	if err != nil {
		log.WithFields(logEntry).WithError(err).Error("LREM command failed")
		return err
	}

	return nil
}

// GetListRange gets range of elements of list identified by keyName
func (r *RedisCluster) GetListRange(keyName string, from, to int64) ([]string, error) {
	fixedKey := r.fixKey(keyName)
	logEntry := logrus.Fields{
		"keyName":  keyName,
		"fixedKey": fixedKey,
		"from":     from,
		"to":       to,
	}
	log.WithFields(logEntry).Debug("Getting list range")

	storage, err := r.list()
	if err != nil {
		log.Error(err)
		return []string{}, err
	}

	elements, err := storage.Range(context.Background(), fixedKey, from, to)
	if err != nil {
		log.WithFields(logEntry).WithError(err).Error("LRANGE command failed")
		return nil, err
	}

	return elements, nil
}

func (r *RedisCluster) AppendToSetPipelined(key string, values [][]byte) {
	if len(values) == 0 {
		return
	}

	fixedKey := r.fixKey(key)
	storage, err := r.list()
	if err != nil {
		log.Error(err)
		return
	}

	err = storage.Append(context.Background(), true, fixedKey, values...)
	if err != nil {
		log.WithError(err).Error("Error trying to append to set keys")
	}
}

func (r *RedisCluster) GetSet(keyName string) (map[string]string, error) {
	log.Debug("Getting from key set: ", keyName)
	log.Debug("Getting from fixed key set: ", r.fixKey(keyName))
	storage, err := r.set()
	if err != nil {
		log.Error(err)
		return nil, err
	}

	members, err := storage.Members(context.Background(), r.fixKey(keyName))
	if err != nil {
		log.Error("Error trying to get key set:", err)
		return nil, err
	}

	result := make(map[string]string)
	for i, value := range members {
		result[strconv.Itoa(i)] = value
	}

	return result, nil
}

func (r *RedisCluster) AddToSet(keyName, value string) {
	log.Debug("Pushing to raw key set: ", keyName)
	log.Debug("Pushing to fixed key set: ", r.fixKey(keyName))
	storage, err := r.set()
	if err != nil {
		log.Error(err)
		return
	}

	err = storage.AddMember(context.Background(), r.fixKey(keyName), value)
	if err != nil {
		log.Error("Error trying to append to set: ", err)
	}
}

func (r *RedisCluster) RemoveFromSet(keyName, value string) {
	log.Debug("Removing from raw key set: ", keyName)
	log.Debug("Removing from fixed key set: ", r.fixKey(keyName))
	storage, err := r.set()
	if err != nil {
		log.Error(err)
		return
	}

	err = storage.RemoveMember(context.Background(), r.fixKey(keyName), value)
	if err != nil {
		log.Error("Error trying to remove keys: ", err)
	}
}

func (r *RedisCluster) IsMemberOfSet(keyName, value string) bool {
	storage, err := r.set()
	if err != nil {
		log.Error(err)
		return false
	}

	val, err := storage.IsMember(context.Background(), r.fixKey(keyName), value)
	if err != nil {
		log.Error("Error trying to check set member: ", err)
		return false
	}

	log.Debug("SISMEMBER", keyName, value, val, err)

	return val
}

// SetRollingWindow will append to a sorted set in redis and extract a timed window of values
func (r *RedisCluster) SetRollingWindow(keyName string, per int64, value_override string, pipeline bool) (int, []interface{}) {
	log.Debug("Incrementing raw key: ", keyName)
	log.Debug("keyName is: ", keyName)
	now := time.Now()
	log.Debug("Now is:", now)
	onePeriodAgo := now.Add(time.Duration(-1*per) * time.Second)
	log.Debug("Then is: ", onePeriodAgo)

	singleton, err := r.Client()
	if err != nil {
		log.Error(err)
		return 0, nil
	}

	ctx := context.Background()
	var zrange *redis.StringSliceCmd

	pipeFn := func(pipe redis.Pipeliner) error {
		pipe.ZRemRangeByScore(ctx, keyName, "-inf", strconv.Itoa(int(onePeriodAgo.UnixNano())))
		zrange = pipe.ZRange(ctx, keyName, 0, -1)

		element := redis.Z{
			Score: float64(now.UnixNano()),
		}

		if value_override != "-1" {
			element.Member = value_override
		} else {
			element.Member = strconv.Itoa(int(now.UnixNano()))
		}

		pipe.ZAdd(ctx, keyName, element)
		pipe.Expire(ctx, keyName, time.Duration(per)*time.Second)

		return nil
	}

	if pipeline {
		_, err = singleton.Pipelined(context.Background(), pipeFn)
	} else {
		_, err = singleton.TxPipelined(context.Background(), pipeFn)
	}

	if err != nil {
		log.Error("Multi command failed: ", err)
		return 0, nil
	}

	values := zrange.Val()

	// Check actual value
	if values == nil {
		return 0, nil
	}

	intVal := len(values)
	result := make([]interface{}, len(values))

	for i, v := range values {
		result[i] = v
	}

	log.Debug("Returned: ", intVal)

	return intVal, result
}

func (r *RedisCluster) GetRollingWindow(keyName string, per int64, pipeline bool) (int, []interface{}) {
	now := time.Now()
	onePeriodAgo := now.Add(time.Duration(-1*per) * time.Second)

	singleton, err := r.Client()
	if err != nil {
		log.Error(err)
		return 0, nil
	}
	ctx := context.Background()

	var zrange *redis.StringSliceCmd

	pipeFn := func(pipe redis.Pipeliner) error {
		pipe.ZRemRangeByScore(ctx, keyName, "-inf", strconv.Itoa(int(onePeriodAgo.UnixNano())))
		zrange = pipe.ZRange(ctx, keyName, 0, -1)

		return nil
	}

	if pipeline {
		_, err = singleton.Pipelined(ctx, pipeFn)
	} else {
		_, err = singleton.TxPipelined(ctx, pipeFn)
	}
	if err != nil {
		log.Error("Multi command failed: ", err)
		return 0, nil
	}

	values := zrange.Val()

	// Check actual value
	if values == nil {
		return 0, nil
	}

	intVal := len(values)
	result := make([]interface{}, intVal)
	for i, v := range values {
		result[i] = v
	}

	log.Debug("Returned: ", intVal)

	return intVal, result
}

// GetPrefix returns storage key prefix
func (r *RedisCluster) GetKeyPrefix() string {
	return r.KeyPrefix
}

// AddToSortedSet adds value with given score to sorted set identified by keyName
func (r *RedisCluster) AddToSortedSet(keyName, value string, score float64) {
	fixedKey := r.fixKey(keyName)
	logEntry := logrus.Fields{
		"keyName":  keyName,
		"fixedKey": fixedKey,
	}
	log.WithFields(logEntry).Debug("Pushing raw key to sorted set")

	storage, err := r.sortedSet()
	if err != nil {
		log.Error(err)
		return
	}

	_, err = storage.AddScoredMember(context.Background(), fixedKey, value, score)
	if err != nil {
		log.WithFields(logEntry).WithError(err).Error("ZADD command failed")
	}
}

// GetSortedSetRange gets range of elements of sorted set identified by keyName
func (r *RedisCluster) GetSortedSetRange(keyName, scoreFrom, scoreTo string) ([]string, []float64, error) {
	fixedKey := r.fixKey(keyName)
	logEntry := logrus.Fields{
		"keyName":   keyName,
		"fixedKey":  fixedKey,
		"scoreFrom": scoreFrom,
		"scoreTo":   scoreTo,
	}
	log.WithFields(logEntry).Debug("Getting sorted set range")

	storage, err := r.sortedSet()
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}

	values, scores, err := storage.GetMembersByScoreRange(context.Background(), fixedKey, scoreFrom, scoreTo)
	if err != nil {
		log.WithFields(logEntry).WithError(err).Error("ZRANGEBYSCORE command failed")
		return nil, nil, err
	}

	if len(values) == 0 {
		return nil, nil, nil
	}

	elements := make([]string, len(values))

	for i, v := range values {
		elements[i] = fmt.Sprint(v)
	}

	return elements, scores, nil
}

// RemoveSortedSetRange removes range of elements from sorted set identified by keyName
func (r *RedisCluster) RemoveSortedSetRange(keyName, scoreFrom, scoreTo string) error {
	fixedKey := r.fixKey(keyName)
	logEntry := logrus.Fields{
		"keyName":   keyName,
		"fixedKey":  fixedKey,
		"scoreFrom": scoreFrom,
		"scoreTo":   scoreTo,
	}
	log.WithFields(logEntry).Debug("Removing sorted set range")

	storage, err := r.sortedSet()
	if err != nil {
		log.Error(err)
		return err
	}

	_, err = storage.RemoveMembersByScoreRange(context.Background(), fixedKey, scoreFrom, scoreTo)
	if err != nil {
		log.WithFields(logEntry).WithError(err).Error("ZREMRANGEBYSCORE command failed")
		return err
	}

	return nil
}

func (r *RedisCluster) ControllerInitiated() bool {
	return r.getConnectionHandler() != nil
}

// ScanKeys will return all keys according to the pattern.
func (r *RedisCluster) ScanKeys(pattern string) ([]string, error) {
	storage, err := r.kv()
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return storage.Keys(context.Background(), pattern)
}
