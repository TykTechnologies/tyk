package main

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/garyburd/redigo/redis"
	"github.com/lonelycode/redigocluster/rediscluster"
)

// ------------------- REDIS CLUSTER STORAGE MANAGER -------------------------------

var redisClusterSingleton *rediscluster.RedisCluster
var redisCacheClusterSingleton *rediscluster.RedisCluster

func GetRelevantClusterReference(cache bool) *rediscluster.RedisCluster {
	if cache {
		return redisCacheClusterSingleton
	}

	return redisClusterSingleton
}

// RedisClusterStorageManager is a storage manager that uses the redis database.
type RedisClusterStorageManager struct {
	KeyPrefix string
	HashKeys  bool
	IsCache   bool
}

func NewRedisClusterPool(forceReconnect bool, isCache bool) *rediscluster.RedisCluster {
	redisPtr := redisClusterSingleton
	cfg := globalConf.Storage
	if isCache && globalConf.EnableSeperateCacheStore {
		redisPtr = redisCacheClusterSingleton
		cfg = globalConf.CacheStorage
	}

	if !forceReconnect {
		if redisPtr != nil {
			log.Debug("Redis pool already INITIALISED")
			return redisPtr
		}
	} else if redisPtr != nil {
		redisPtr.CloseConnection()
	}

	log.Debug("Creating new Redis connection pool")

	maxIdle := 100
	if cfg.MaxIdle > 0 {
		maxIdle = cfg.MaxIdle
	}

	maxActive := 500
	if cfg.MaxActive > 0 {
		maxActive = cfg.MaxActive
	}

	if cfg.EnableCluster {
		log.Info("--> Using clustered mode")
	}

	poolConf := rediscluster.PoolConfig{
		MaxIdle:     maxIdle,
		MaxActive:   maxActive,
		IdleTimeout: 240 * time.Second,
		Database:    cfg.Database,
		Password:    cfg.Password,
		IsCluster:   cfg.EnableCluster,
	}

	seed_redii := []map[string]string{}

	for h, p := range cfg.Hosts {
		seed_redii = append(seed_redii, map[string]string{h: p})
	}
	if len(seed_redii) == 0 {
		seed_redii = append(seed_redii, map[string]string{cfg.Host: strconv.Itoa(cfg.Port)})
	}

	cluster := rediscluster.NewRedisCluster(seed_redii, poolConf, false)
	return &cluster
}

// Connect will establish a connection to the GetRelevantClusterReference(r.IsCache)
func (r *RedisClusterStorageManager) Connect() bool {
	if GetRelevantClusterReference(r.IsCache) == nil {
		log.Debug("Connecting to redis cluster")
		if r.IsCache {
			redisCacheClusterSingleton = NewRedisClusterPool(false, r.IsCache)
			return true
		}
		redisClusterSingleton = NewRedisClusterPool(false, r.IsCache)
		return true
	}

	log.Debug("Storage Engine already initialised...")
	return true
}

func (r *RedisClusterStorageManager) hashKey(in string) string {
	if !r.HashKeys {
		// Not hashing? Return the raw key
		return in
	}
	return doHash(in)
}

func (r *RedisClusterStorageManager) fixKey(keyName string) string {
	setKeyName := r.KeyPrefix + r.hashKey(keyName)

	log.Debug("Input key was: ", setKeyName)

	return setKeyName
}

func (r *RedisClusterStorageManager) cleanKey(keyName string) string {
	setKeyName := strings.Replace(keyName, r.KeyPrefix, "", 1)
	return setKeyName
}

func (r *RedisClusterStorageManager) ensureConnection() {
	if GetRelevantClusterReference(r.IsCache) != nil {
		// already connected
		return
	}
	log.Info("Connection dropped, reconnecting...")
	for {
		r.Connect()
		if GetRelevantClusterReference(r.IsCache) != nil {
			// reconnection worked
			return
		}
		log.Info("Reconnecting again...")
	}
}

// GetKey will retrieve a key from the database
func (r *RedisClusterStorageManager) GetKey(keyName string) (string, error) {
	r.ensureConnection()
	log.Debug("[STORE] Getting WAS: ", keyName)
	log.Debug("[STORE] Getting: ", r.fixKey(keyName))
	value, err := redis.String(GetRelevantClusterReference(r.IsCache).Do("GET", r.fixKey(keyName)))
	if err != nil {
		log.Debug("Error trying to get value:", err)
		return "", errKeyNotFound
	}

	return value, nil
}

func (r *RedisClusterStorageManager) GetKeyTTL(keyName string) (ttl int64, err error) {
	r.ensureConnection()
	return redis.Int64(GetRelevantClusterReference(r.IsCache).Do("TTL", r.fixKey(keyName)))
}

func (r *RedisClusterStorageManager) GetRawKey(keyName string) (string, error) {
	r.ensureConnection()
	value, err := redis.String(GetRelevantClusterReference(r.IsCache).Do("GET", keyName))
	if err != nil {
		log.Debug("Error trying to get value:", err)
		return "", errKeyNotFound
	}

	return value, nil
}

func (r *RedisClusterStorageManager) GetExp(keyName string) (int64, error) {
	log.Debug("Getting exp for key: ", r.fixKey(keyName))
	r.ensureConnection()

	value, err := redis.Int64(GetRelevantClusterReference(r.IsCache).Do("TTL", r.fixKey(keyName)))
	if err != nil {
		log.Error("Error trying to get TTL: ", err)
		return 0, errKeyNotFound
	}
	return value, nil

}

// SetKey will create (or update) a key value in the store
func (r *RedisClusterStorageManager) SetKey(keyName, sessionState string, timeout int64) error {
	log.Debug("[STORE] SET Raw key is: ", keyName)
	log.Debug("[STORE] Setting key: ", r.fixKey(keyName))

	r.ensureConnection()
	_, err := GetRelevantClusterReference(r.IsCache).Do("SET", r.fixKey(keyName), sessionState)
	if timeout > 0 {
		_, err := GetRelevantClusterReference(r.IsCache).Do("EXPIRE", r.fixKey(keyName), timeout)
		if err != nil {
			log.Error("Could not EXPIRE key: ", err)
			return err
		}
	}
	if err != nil {
		log.Error("Error trying to set value: ", err)
		return err
	}
	return nil
}

func (r *RedisClusterStorageManager) SetRawKey(keyName, sessionState string, timeout int64) error {

	r.ensureConnection()
	_, err := GetRelevantClusterReference(r.IsCache).Do("SET", keyName, sessionState)
	if timeout > 0 {
		_, err := GetRelevantClusterReference(r.IsCache).Do("EXPIRE", keyName, timeout)
		if err != nil {
			log.Error("Could not EXPIRE key: ", err)
			return err
		}
	}
	if err != nil {
		log.Error("Error trying to set value: ", err)
		return err
	}
	return nil
}

// Decrement will decrement a key in redis
func (r *RedisClusterStorageManager) Decrement(keyName string) {

	keyName = r.fixKey(keyName)
	log.Debug("Decrementing key: ", keyName)
	r.ensureConnection()
	err := GetRelevantClusterReference(r.IsCache).Send("DECR", keyName)
	if err != nil {
		log.Error("Error trying to decrement value:", err)
	}
}

// IncrementWithExpire will increment a key in redis
func (r *RedisClusterStorageManager) IncrememntWithExpire(keyName string, expire int64) int64 {

	log.Debug("Incrementing raw key: ", keyName)
	r.ensureConnection()
	// This function uses a raw key, so we shouldn't call fixKey
	fixedKey := keyName
	val, err := redis.Int64(GetRelevantClusterReference(r.IsCache).Do("INCR", fixedKey))
	log.Debug("Incremented key: ", fixedKey, ", val is: ", val)
	if val == 1 {
		log.Debug("--> Setting Expire")
		GetRelevantClusterReference(r.IsCache).Do("EXPIRE", fixedKey, expire)
	}
	if err != nil {
		log.Error("Error trying to increment value:", err)
	}
	return val
}

// GetKeys will return all keys according to the filter (filter is a prefix - e.g. tyk.keys.*)
func (r *RedisClusterStorageManager) GetKeys(filter string) []string {
	r.ensureConnection()
	searchStr := r.KeyPrefix + r.hashKey(filter) + "*"
	sessionsInterface, err := GetRelevantClusterReference(r.IsCache).Do("KEYS", searchStr)
	if err != nil {
		log.Error("Error trying to get all keys: ", err)
		return nil

	}
	sessions, _ := redis.Strings(sessionsInterface, err)
	for i, v := range sessions {
		sessions[i] = r.cleanKey(v)
	}
	return sessions
}

// GetKeysAndValuesWithFilter will return all keys and their values with a filter
func (r *RedisClusterStorageManager) GetKeysAndValuesWithFilter(filter string) map[string]string {
	r.ensureConnection()
	searchStr := r.KeyPrefix + r.hashKey(filter) + "*"
	log.Debug("[STORE] Getting list by: ", searchStr)
	sessionsInterface, err := GetRelevantClusterReference(r.IsCache).Do("KEYS", searchStr)
	if err != nil {
		log.Error("Error trying to get filtered client keys: ", err)
		return nil
	}

	keys, _ := redis.Strings(sessionsInterface, err)
	valueObj, err := GetRelevantClusterReference(r.IsCache).Do("MGET", sessionsInterface.([]interface{})...)
	values, err := redis.Strings(valueObj, err)
	if err != nil {
		log.Error("Error trying to get filtered client keys: ", err)
		return nil
	}

	m := make(map[string]string)
	for i, v := range keys {
		m[r.cleanKey(v)] = values[i]
	}
	return m
}

// GetKeysAndValues will return all keys and their values - not to be used lightly
func (r *RedisClusterStorageManager) GetKeysAndValues() map[string]string {
	r.ensureConnection()
	searchStr := r.KeyPrefix + "*"
	sessionsInterface, err := GetRelevantClusterReference(r.IsCache).Do("KEYS", searchStr)
	if err != nil {
		log.Error("Error trying to get all keys: ", err)
		return nil
	}
	keys, _ := redis.Strings(sessionsInterface, err)
	valueObj, err := GetRelevantClusterReference(r.IsCache).Do("MGET", sessionsInterface.([]interface{})...)
	values, err := redis.Strings(valueObj, err)
	if err != nil {
		log.Error("Error trying to get all keys: ", err)
		return nil
	}

	m := make(map[string]string)
	for i, v := range keys {
		m[r.cleanKey(v)] = values[i]
	}
	return m
}

// DeleteKey will remove a key from the database
func (r *RedisClusterStorageManager) DeleteKey(keyName string) bool {
	r.ensureConnection()
	log.Debug("DEL Key was: ", keyName)
	log.Debug("DEL Key became: ", r.fixKey(keyName))
	_, err := GetRelevantClusterReference(r.IsCache).Do("DEL", r.fixKey(keyName))
	if err != nil {
		log.Error("Error trying to delete key: ", err)
	}

	return true
}

// DeleteKey will remove a key from the database without prefixing, assumes user knows what they are doing
func (r *RedisClusterStorageManager) DeleteRawKey(keyName string) bool {
	r.ensureConnection()
	_, err := GetRelevantClusterReference(r.IsCache).Do("DEL", keyName)
	if err != nil {
		log.Error("Error trying to delete key: ", err)
	}

	return true
}

// DeleteKeys will remove a group of keys in bulk
func (r *RedisClusterStorageManager) DeleteScanMatch(pattern string) bool {
	r.ensureConnection()
	log.Debug("Deleting: ", pattern)

	// here we'll store our iterator value
	iter := "0"

	// this will store the keys of each iteration
	var keys []string
	for {
		// we scan with our iter offset, starting at 0
		arr, err := redis.MultiBulk(GetRelevantClusterReference(r.IsCache).Do("SCAN", iter, "MATCH", pattern))
		if err != nil {
			log.Error("SCAN Token Get Failure: ", err)
			return false
		}
		// now we get the iter and the keys from the multi-bulk reply
		iter, _ = redis.String(arr[0], nil)
		theseKeys, _ := redis.Strings(arr[1], nil)
		keys = append(keys, theseKeys...)

		// check if we need to stop...
		if iter == "0" {
			break
		}
	}

	if len(keys) > 0 {
		for _, name := range keys {
			log.Info("Deleting: ", name)
			_, err := GetRelevantClusterReference(r.IsCache).Do("DEL", name)
			if err != nil {
				log.Error("Error trying to delete key: ", name, " - ", err)

			}
		}
		log.Info("Deleted: ", len(keys), " records")
	} else {
		log.Debug("RedisClusterStorageManager called DEL - Nothing to delete")
	}

	return true
}

// DeleteKeys will remove a group of keys in bulk
func (r *RedisClusterStorageManager) DeleteKeys(keys []string) bool {
	r.ensureConnection()
	if len(keys) > 0 {
		asInterface := make([]interface{}, len(keys))
		for i, v := range keys {
			asInterface[i] = interface{}(r.fixKey(v))
		}

		log.Debug("Deleting: ", asInterface)
		_, err := GetRelevantClusterReference(r.IsCache).Do("DEL", asInterface...)
		if err != nil {
			log.Error("Error trying to delete keys: ", err)
		}
	} else {
		log.Debug("RedisClusterStorageManager called DEL - Nothing to delete")
	}

	return true
}

// StartPubSubHandler will listen for a signal and run the callback for
// every subscription and message event.
func (r *RedisClusterStorageManager) StartPubSubHandler(channel string, callback func(interface{})) error {
	if GetRelevantClusterReference(r.IsCache) == nil {
		return errors.New("Redis connection failed")
	}

	handle := GetRelevantClusterReference(r.IsCache).RandomRedisHandle()
	if handle == nil {
		return errors.New("Redis connection failed")
	}

	psc := redis.PubSubConn{
		Conn: GetRelevantClusterReference(r.IsCache).RandomRedisHandle().Pool.Get(),
	}
	if err := psc.Subscribe(channel); err != nil {
		return err
	}
	for {
		switch v := psc.Receive().(type) {
		case redis.Message:
			callback(v)

		case redis.Subscription:
			callback(v)

		case error:
			log.Error("Redis disconnected or error received, attempting to reconnect: ", v)
			return v
		}
	}
}

func (r *RedisClusterStorageManager) Publish(channel, message string) error {
	r.ensureConnection()
	_, err := GetRelevantClusterReference(r.IsCache).Do("PUBLISH", channel, message)
	if err != nil {
		log.Error("Error trying to set value: ", err)
		return err
	}
	return nil
}

func (r *RedisClusterStorageManager) GetAndDeleteSet(keyName string) []interface{} {
	log.Debug("Getting raw key set: ", keyName)
	r.ensureConnection()
	log.Debug("keyName is: ", keyName)
	fixedKey := r.fixKey(keyName)
	log.Debug("Fixed keyname is: ", fixedKey)

	lrange := rediscluster.ClusterTransaction{}
	lrange.Cmd = "LRANGE"
	lrange.Args = []interface{}{fixedKey, 0, -1}

	delCmd := rediscluster.ClusterTransaction{}
	delCmd.Cmd = "DEL"
	delCmd.Args = []interface{}{fixedKey}

	redVal, err := redis.Values(GetRelevantClusterReference(r.IsCache).DoTransaction([]rediscluster.ClusterTransaction{lrange, delCmd}))
	if err != nil {
		log.Error("Multi command failed: ", err)
		return nil
	}

	log.Debug("Analytics returned: ", redVal)
	if len(redVal) == 0 {
		return nil
	}

	vals := redVal[0].([]interface{})

	log.Debug("Unpacked vals: ", vals)

	return vals
}

func (r *RedisClusterStorageManager) AppendToSet(keyName, value string) {
	log.Debug("Pushing to raw key list: ", keyName)
	log.Debug("Appending to fixed key list: ", r.fixKey(keyName))
	r.ensureConnection()
	_, err := GetRelevantClusterReference(r.IsCache).Do("RPUSH", r.fixKey(keyName), value)

	if err != nil {
		log.Error("Error trying to delete keys: ", err)
	}
}

func (r *RedisClusterStorageManager) GetSet(keyName string) (map[string]string, error) {
	log.Debug("Getting from key set: ", keyName)
	log.Debug("Getting from fixed key set: ", r.fixKey(keyName))
	r.ensureConnection()
	val, err := GetRelevantClusterReference(r.IsCache).Do("SMEMBERS", r.fixKey(keyName))
	if err != nil {
		log.Error("Error trying to get key set:", err)
		return nil, err
	}

	asValues, _ := redis.Strings(val, err)

	vals := make(map[string]string)
	for i, value := range asValues {
		vals[strconv.Itoa(i)] = value
	}
	return vals, nil
}

func (r *RedisClusterStorageManager) AddToSet(keyName, value string) {
	log.Debug("Pushing to raw key set: ", keyName)
	log.Debug("Pushing to fixed key set: ", r.fixKey(keyName))
	r.ensureConnection()
	_, err := GetRelevantClusterReference(r.IsCache).Do("SADD", r.fixKey(keyName), value)

	if err != nil {
		log.Error("Error trying to append keys: ", err)
	}
}

func (r *RedisClusterStorageManager) RemoveFromSet(keyName, value string) {
	log.Debug("Removing from raw key set: ", keyName)
	log.Debug("Removing from fixed key set: ", r.fixKey(keyName))
	r.ensureConnection()
	_, err := GetRelevantClusterReference(r.IsCache).Do("SREM", r.fixKey(keyName), value)

	if err != nil {
		log.Error("Error trying to remove keys: ", err)
	}
}

// SetRollingWindow will append to a sorted set in redis and extract a timed window of values
func (r *RedisClusterStorageManager) SetRollingWindow(keyName string, per int64, value_override string) (int, []interface{}) {

	log.Debug("Incrementing raw key: ", keyName)
	r.ensureConnection()
	log.Debug("keyName is: ", keyName)
	now := time.Now()
	log.Debug("Now is:", now)
	onePeriodAgo := now.Add(time.Duration(-1*per) * time.Second)
	log.Debug("Then is: ", onePeriodAgo)

	ZREMRANGEBYSCORE := rediscluster.ClusterTransaction{}
	ZREMRANGEBYSCORE.Cmd = "ZREMRANGEBYSCORE"
	ZREMRANGEBYSCORE.Args = []interface{}{keyName, "-inf", onePeriodAgo.UnixNano()}

	ZRANGE := rediscluster.ClusterTransaction{}
	ZRANGE.Cmd = "ZRANGE"
	ZRANGE.Args = []interface{}{keyName, 0, -1}

	ZADD := rediscluster.ClusterTransaction{}
	ZADD.Cmd = "ZADD"

	if value_override != "-1" {
		ZADD.Args = []interface{}{keyName, now.UnixNano(), value_override}
	} else {
		ZADD.Args = []interface{}{keyName, now.UnixNano(), strconv.Itoa(int(now.UnixNano()))}
	}

	EXPIRE := rediscluster.ClusterTransaction{}
	EXPIRE.Cmd = "EXPIRE"
	EXPIRE.Args = []interface{}{keyName, per}

	redVal, err := redis.Values(GetRelevantClusterReference(r.IsCache).DoTransaction([]rediscluster.ClusterTransaction{ZREMRANGEBYSCORE, ZRANGE, ZADD, EXPIRE}))
	if err != nil {
		log.Error("Multi command failed: ", err)
		return 0, nil
	}

	if len(redVal) < 2 {
		log.Error("Multi command failed: return index is out of range")
		return 0, nil
	}

	// Check actual value
	if redVal[1] == nil {
		return 0, nil
	}

	intVal := len(redVal[1].([]interface{}))

	log.Debug("Returned: ", intVal)

	return intVal, redVal[1].([]interface{})
}

func (r *RedisClusterStorageManager) SetRollingWindowPipeline(keyName string, per int64, value_override string) (int, []interface{}) {

	log.Debug("Incrementing raw key: ", keyName)
	r.ensureConnection()
	log.Debug("keyName is: ", keyName)
	now := time.Now()
	log.Debug("Now is:", now)
	onePeriodAgo := now.Add(time.Duration(-1*per) * time.Second)
	log.Debug("Then is: ", onePeriodAgo)

	ZREMRANGEBYSCORE := rediscluster.ClusterTransaction{}
	ZREMRANGEBYSCORE.Cmd = "ZREMRANGEBYSCORE"
	ZREMRANGEBYSCORE.Args = []interface{}{keyName, "-inf", onePeriodAgo.UnixNano()}

	ZRANGE := rediscluster.ClusterTransaction{}
	ZRANGE.Cmd = "ZRANGE"
	ZRANGE.Args = []interface{}{keyName, 0, -1}

	ZADD := rediscluster.ClusterTransaction{}
	ZADD.Cmd = "ZADD"

	if value_override != "-1" {
		ZADD.Args = []interface{}{keyName, now.UnixNano(), value_override}
	} else {
		ZADD.Args = []interface{}{keyName, now.UnixNano(), strconv.Itoa(int(now.UnixNano()))}
	}

	EXPIRE := rediscluster.ClusterTransaction{}
	EXPIRE.Cmd = "EXPIRE"
	EXPIRE.Args = []interface{}{keyName, per}

	redVal, err := redis.Values(GetRelevantClusterReference(r.IsCache).DoPipeline([]rediscluster.ClusterTransaction{ZREMRANGEBYSCORE, ZRANGE, ZADD, EXPIRE}))
	if err != nil {
		log.Error("Multi command failed: ", err)
		return 0, nil
	}

	if len(redVal) < 2 {
		log.Error("Multi command failed: return index is out of range")
		return 0, nil
	}

	// Check actual value
	if redVal[1] == nil {
		return 0, nil
	}

	// All clear
	intVal := len(redVal[1].([]interface{}))
	log.Debug("Returned: ", intVal)

	return intVal, redVal[1].([]interface{})
}
