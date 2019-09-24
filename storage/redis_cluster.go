package storage

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/garyburd/redigo/redis"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/redigocluster/rediscluster"
	"github.com/TykTechnologies/tyk/config"
)

// ------------------- REDIS CLUSTER STORAGE MANAGER -------------------------------

const (
	waitStorageRetriesNum      = 5
	waitStorageRetriesInterval = 1 * time.Second

	defaultRedisPort = 6379
)

var (
	redisSingletonMu sync.RWMutex

	redisClusterSingleton      *rediscluster.RedisCluster
	redisCacheClusterSingleton *rediscluster.RedisCluster
)

// RedisCluster is a storage manager that uses the redis database.
type RedisCluster struct {
	KeyPrefix string
	HashKeys  bool
	IsCache   bool
}

func clusterConnectionIsOpen(cluster *RedisCluster) bool {
	testKey := "redis-test-" + uuid.NewV4().String()
	// set test key
	if err := cluster.SetKey(testKey, "test", 1); err != nil {
		return false
	}
	// get test key
	if _, err := cluster.GetKey(testKey); err != nil {
		return false
	}
	return true
}

// IsConnected waits with retries until Redis connection pools are connected
func IsConnected() bool {
	// create temporary ones to access singletons
	testClusters := []*RedisCluster{
		{},
	}
	if config.Global().EnableSeperateCacheStore {
		testClusters = append(testClusters, &RedisCluster{IsCache: true})
	}
	for _, cluster := range testClusters {
		cluster.Connect()
	}

	// wait for connection pools with retries
	retryNum := 0
	for {
		if retryNum == waitStorageRetriesNum {
			log.Error("Waiting for Redis connection pools failed")
			return false
		}

		// check that redis is available
		var redisIsReady bool
		for _, cluster := range testClusters {
			redisIsReady = cluster.singleton() != nil && clusterConnectionIsOpen(cluster)
			if !redisIsReady {
				break
			}
		}
		if redisIsReady {
			break
		}

		// sleep before next check
		log.WithField("currRetry", retryNum).Info("Waiting for Redis connection pools to be ready")
		time.Sleep(waitStorageRetriesInterval)
		retryNum++
	}
	log.WithField("currRetry", retryNum).Info("Redis connection pools are ready after number of retires")

	return true
}

func NewRedisClusterPool(isCache bool) *rediscluster.RedisCluster {
	// redisSingletonMu is locked and we know the singleton is nil
	cfg := config.Global().Storage
	if isCache && config.Global().EnableSeperateCacheStore {
		cfg = config.Global().CacheStorage
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

	timeout := 5 * time.Second

	if cfg.Timeout > 0 {
		timeout = time.Duration(cfg.Timeout) * time.Second
	}

	poolConf := rediscluster.PoolConfig{
		MaxIdle:        maxIdle,
		MaxActive:      maxActive,
		IdleTimeout:    240 * time.Second,
		ConnectTimeout: timeout,
		ReadTimeout:    timeout,
		WriteTimeout:   timeout,
		Database:       cfg.Database,
		Password:       cfg.Password,
		IsCluster:      cfg.EnableCluster,
		UseTLS:         cfg.UseSSL,
		TLSSkipVerify:  cfg.SSLInsecureSkipVerify,
	}

	// If Redis port isn't set, use default one:
	if cfg.Port == 0 {
		cfg.Port = defaultRedisPort
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

// Connect will establish a connection to the r.singleton()
func (r *RedisCluster) Connect() bool {
	redisSingletonMu.Lock()
	defer redisSingletonMu.Unlock()
	disconnected := redisClusterSingleton == nil
	if r.IsCache {
		disconnected = redisCacheClusterSingleton == nil
	}
	if disconnected {
		log.Debug("Connecting to redis cluster")
		if r.IsCache {
			redisCacheClusterSingleton = NewRedisClusterPool(true)
			return true
		}
		redisClusterSingleton = NewRedisClusterPool(false)
		return true
	}

	log.Debug("Storage Engine already initialised...")
	return true
}

func (r *RedisCluster) singleton() *rediscluster.RedisCluster {
	redisSingletonMu.RLock()
	defer redisSingletonMu.RUnlock()
	if r.IsCache {
		return redisCacheClusterSingleton
	}
	return redisClusterSingleton
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

func (r *RedisCluster) ensureConnection() {
	if r.singleton() != nil {
		// already connected
		return
	}
	log.Info("Connection dropped, reconnecting...")
	for {
		r.Connect()
		if r.singleton() != nil {
			// reconnection worked
			return
		}
		log.Info("Reconnecting again...")
	}
}

// GetKey will retrieve a key from the database
func (r *RedisCluster) GetKey(keyName string) (string, error) {
	r.ensureConnection()
	log.Debug("[STORE] Getting WAS: ", keyName)
	log.Debug("[STORE] Getting: ", r.fixKey(keyName))
	cluster := r.singleton()

	value, err := redis.String(cluster.Do("GET", r.fixKey(keyName)))

	if err != nil {
		log.Debug("Error trying to get value:", err)
		return "", ErrKeyNotFound
	}

	return value, nil
}

// GetMultiKey gets multiple keys from the database
func (r *RedisCluster) GetMultiKey(keyNames []string) ([]string, error) {
	r.ensureConnection()
	cluster := r.singleton()

	fixedKeyNames := make([]interface{}, len(keyNames))
	for index, val := range keyNames {
		fixedKeyNames[index] = r.fixKey(val)
	}

	value, err := redis.Strings(cluster.Do("MGET", fixedKeyNames...))
	if err != nil {
		log.WithError(err).Debug("Error trying to get value")
		return nil, ErrKeyNotFound
	}
	for _, v := range value {
		if v != "" {
			return value, nil
		}
	}
	return nil, ErrKeyNotFound
}

func (r *RedisCluster) GetKeyTTL(keyName string) (ttl int64, err error) {
	r.ensureConnection()
	return redis.Int64(r.singleton().Do("TTL", r.fixKey(keyName)))
}

func (r *RedisCluster) GetRawKey(keyName string) (string, error) {
	r.ensureConnection()
	value, err := redis.String(r.singleton().Do("GET", keyName))
	if err != nil {
		log.Debug("Error trying to get value:", err)
		return "", ErrKeyNotFound
	}

	return value, nil
}

func (r *RedisCluster) GetExp(keyName string) (int64, error) {
	log.Debug("Getting exp for key: ", r.fixKey(keyName))
	r.ensureConnection()

	value, err := redis.Int64(r.singleton().Do("TTL", r.fixKey(keyName)))
	if err != nil {
		log.Error("Error trying to get TTL: ", err)
		return 0, ErrKeyNotFound
	}
	return value, nil
}

func (r *RedisCluster) SetExp(keyName string, timeout int64) error {
	_, err := r.singleton().Do("EXPIRE", r.fixKey(keyName), timeout)
	if err != nil {
		log.Error("Could not EXPIRE key: ", err)
	}
	return err
}

// SetKey will create (or update) a key value in the store
func (r *RedisCluster) SetKey(keyName, session string, timeout int64) error {
	log.Debug("[STORE] SET Raw key is: ", keyName)
	log.Debug("[STORE] Setting key: ", r.fixKey(keyName))

	r.ensureConnection()
	_, err := r.singleton().Do("SET", r.fixKey(keyName), session)
	if timeout > 0 {
		if err := r.SetExp(keyName, timeout); err != nil {
			return err
		}
	}
	if err != nil {
		log.Error("Error trying to set value: ", err)
		return err
	}
	return nil
}

func (r *RedisCluster) SetRawKey(keyName, session string, timeout int64) error {
	r.ensureConnection()
	_, err := r.singleton().Do("SET", keyName, session)
	if timeout > 0 {
		_, err := r.singleton().Do("EXPIRE", keyName, timeout)
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
func (r *RedisCluster) Decrement(keyName string) {
	keyName = r.fixKey(keyName)
	log.Debug("Decrementing key: ", keyName)
	r.ensureConnection()
	err := r.singleton().Send("DECR", keyName)
	if err != nil {
		log.Error("Error trying to decrement value:", err)
	}
}

// IncrementWithExpire will increment a key in redis
func (r *RedisCluster) IncrememntWithExpire(keyName string, expire int64) int64 {
	log.Debug("Incrementing raw key: ", keyName)
	r.ensureConnection()
	// This function uses a raw key, so we shouldn't call fixKey
	fixedKey := keyName
	val, err := redis.Int64(r.singleton().Do("INCR", fixedKey))
	log.Debug("Incremented key: ", fixedKey, ", val is: ", val)
	if val == 1 && expire != 0 {
		log.Debug("--> Setting Expire")
		r.singleton().Do("EXPIRE", fixedKey, expire)
	}
	if err != nil {
		log.Error("Error trying to increment value:", err)
	}
	return val
}

// GetKeys will return all keys according to the filter (filter is a prefix - e.g. tyk.keys.*)
func (r *RedisCluster) GetKeys(filter string) []string {
	r.ensureConnection()
	filterHash := ""
	if filter != "" {
		filterHash = r.hashKey(filter)
	}
	searchStr := r.KeyPrefix + filterHash + "*"
	sessionsInterface, err := r.singleton().Do("KEYS", searchStr)
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
func (r *RedisCluster) GetKeysAndValuesWithFilter(filter string) map[string]string {
	r.ensureConnection()
	filterHash := ""
	if filter != "" {
		filterHash = r.hashKey(filter)
	}
	searchStr := r.KeyPrefix + filterHash + "*"
	log.Debug("[STORE] Getting list by: ", searchStr)
	sessionsInterface, err := r.singleton().Do("KEYS", searchStr)
	if err != nil {
		log.Error("Error trying to get filtered client keys: ", err)
		return nil
	}

	keys, _ := redis.Strings(sessionsInterface, err)
	if len(keys) == 0 {
		return nil
	}
	valueObj, err := r.singleton().Do("MGET", sessionsInterface.([]interface{})...)
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
func (r *RedisCluster) GetKeysAndValues() map[string]string {
	r.ensureConnection()
	searchStr := r.KeyPrefix + "*"
	sessionsInterface, err := r.singleton().Do("KEYS", searchStr)
	if err != nil {
		log.Error("Error trying to get all keys: ", err)
		return nil
	}
	keys, _ := redis.Strings(sessionsInterface, err)
	valueObj, err := r.singleton().Do("MGET", sessionsInterface.([]interface{})...)
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
func (r *RedisCluster) DeleteKey(keyName string) bool {
	r.ensureConnection()
	log.Debug("DEL Key was: ", keyName)
	log.Debug("DEL Key became: ", r.fixKey(keyName))
	n, err := r.singleton().Do("DEL", r.fixKey(keyName))
	if err != nil {
		log.WithError(err).Error("Error trying to delete key")
	}

	return n.(int64) > 0
}

// DeleteAllKeys will remove all keys from the database.
func (r *RedisCluster) DeleteAllKeys() bool {
	r.ensureConnection()
	n, err := r.singleton().Do("FLUSHALL")
	if err != nil {
		log.WithError(err).Error("Error trying to delete keys")
	}

	if n.(string) == "OK" {
		return true
	}

	return false
}

// DeleteKey will remove a key from the database without prefixing, assumes user knows what they are doing
func (r *RedisCluster) DeleteRawKey(keyName string) bool {
	r.ensureConnection()
	n, err := r.singleton().Do("DEL", keyName)
	if err != nil {
		log.WithError(err).Error("Error trying to delete key")
	}

	return n.(int64) > 0
}

// DeleteKeys will remove a group of keys in bulk
func (r *RedisCluster) DeleteScanMatch(pattern string) bool {
	r.ensureConnection()
	log.Debug("Deleting: ", pattern)

	// here we'll store our iterator value
	iter := "0"

	// this will store the keys of each iteration
	var keys []string
	for {
		// we scan with our iter offset, starting at 0
		arr, err := redis.MultiBulk(r.singleton().Do("SCAN", iter, "MATCH", pattern))
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
			_, err := r.singleton().Do("DEL", name)
			if err != nil {
				log.Error("Error trying to delete key: ", name, " - ", err)

			}
		}
		log.Info("Deleted: ", len(keys), " records")
	} else {
		log.Debug("RedisCluster called DEL - Nothing to delete")
	}

	return true
}

// DeleteKeys will remove a group of keys in bulk
func (r *RedisCluster) DeleteKeys(keys []string) bool {
	r.ensureConnection()
	if len(keys) > 0 {
		asInterface := make([]interface{}, len(keys))
		for i, v := range keys {
			asInterface[i] = interface{}(r.fixKey(v))
		}

		log.Debug("Deleting: ", asInterface)
		_, err := r.singleton().Do("DEL", asInterface...)
		if err != nil {
			log.Error("Error trying to delete keys: ", err)
		}
	} else {
		log.Debug("RedisCluster called DEL - Nothing to delete")
	}

	return true
}

// StartPubSubHandler will listen for a signal and run the callback for
// every subscription and message event.
func (r *RedisCluster) StartPubSubHandler(channel string, callback func(interface{})) error {
	cluster := r.singleton()
	if cluster == nil {
		return errors.New("Redis connection failed")
	}

	handle := cluster.RandomRedisHandle()
	if handle == nil {
		return errors.New("Redis connection failed. Handle is nil")
	}

	psc := redis.PubSubConn{
		Conn: handle.Pool.Get(),
	}
	if err := psc.Subscribe(channel); err != nil {
		return err
	}
	for {
		switch v := psc.ReceiveWithTimeout(0).(type) {
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

func (r *RedisCluster) Publish(channel, message string) error {
	r.ensureConnection()
	_, err := r.singleton().Do("PUBLISH", channel, message)
	if err != nil {
		log.Error("Error trying to set value: ", err)
		return err
	}
	return nil
}

func (r *RedisCluster) GetAndDeleteSet(keyName string) []interface{} {
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

	redVal, err := redis.Values(r.singleton().DoTransaction([]rediscluster.ClusterTransaction{lrange, delCmd}))
	if err != nil {
		log.Error("Multi command failed: ", err)
		return nil
	}

	log.Debug("Analytics returned: ", len(redVal))
	if len(redVal) == 0 {
		return nil
	}

	vals := redVal[0].([]interface{})

	log.Debug("Unpacked vals: ", vals)

	return vals
}

func (r *RedisCluster) AppendToSet(keyName, value string) {
	fixedKey := r.fixKey(keyName)
	log.WithField("keyName", keyName).Debug("Pushing to raw key list")
	log.WithField("fixedKey", fixedKey).Debug("Appending to fixed key list")
	r.ensureConnection()
	if _, err := r.singleton().Do("RPUSH", fixedKey, value); err != nil {
		log.WithError(err).Error("Error trying to append to set keys")
	}
}

func (r *RedisCluster) AppendToSetPipelined(key string, values []string) {
	if len(values) == 0 {
		return
	}

	fixedKey := r.fixKey(key)

	// prepare pipeline data
	pipeLine := make([]rediscluster.ClusterTransaction, len(values))
	for index, val := range values {
		pipeLine[index] = rediscluster.ClusterTransaction{
			Cmd: "RPUSH",
			Args: []interface{}{
				fixedKey,
				val,
			},
		}
	}

	// send pipelined command to Redis
	r.ensureConnection()
	if _, err := r.singleton().DoPipeline(pipeLine); err != nil {
		log.WithError(err).Error("Error trying to append to set keys")
	}
}

func (r *RedisCluster) GetSet(keyName string) (map[string]string, error) {
	log.Debug("Getting from key set: ", keyName)
	log.Debug("Getting from fixed key set: ", r.fixKey(keyName))
	r.ensureConnection()
	val, err := r.singleton().Do("SMEMBERS", r.fixKey(keyName))
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

func (r *RedisCluster) AddToSet(keyName, value string) {
	log.Debug("Pushing to raw key set: ", keyName)
	log.Debug("Pushing to fixed key set: ", r.fixKey(keyName))
	r.ensureConnection()
	_, err := r.singleton().Do("SADD", r.fixKey(keyName), value)

	if err != nil {
		log.Error("Error trying to append keys: ", err)
	}
}

func (r *RedisCluster) RemoveFromSet(keyName, value string) {
	log.Debug("Removing from raw key set: ", keyName)
	log.Debug("Removing from fixed key set: ", r.fixKey(keyName))
	r.ensureConnection()
	_, err := r.singleton().Do("SREM", r.fixKey(keyName), value)

	if err != nil {
		log.Error("Error trying to remove keys: ", err)
	}
}

func (r *RedisCluster) IsMemberOfSet(keyName, value string) bool {
	r.ensureConnection()
	val, err := redis.Int64(r.singleton().Do("SISMEMBER", r.fixKey(keyName), value))

	if err != nil {
		log.Error("Error trying to check set memeber: ", err)
		return false
	}

	log.Debug("SISMEMBER", keyName, value, val, err)

	return val == 1
}

// SetRollingWindow will append to a sorted set in redis and extract a timed window of values
func (r *RedisCluster) SetRollingWindow(keyName string, per int64, value_override string, pipeline bool) (int, []interface{}) {
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

	var redVal []interface{}
	var err error
	if pipeline {
		redVal, err = redis.Values(r.singleton().DoPipeline([]rediscluster.ClusterTransaction{ZREMRANGEBYSCORE, ZRANGE, ZADD, EXPIRE}))
	} else {
		redVal, err = redis.Values(r.singleton().DoTransaction([]rediscluster.ClusterTransaction{ZREMRANGEBYSCORE, ZRANGE, ZADD, EXPIRE}))
	}
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

func (r RedisCluster) GetRollingWindow(keyName string, per int64, pipeline bool) (int, []interface{}) {
	r.ensureConnection()
	now := time.Now()
	onePeriodAgo := now.Add(time.Duration(-1*per) * time.Second)

	ZREMRANGEBYSCORE := rediscluster.ClusterTransaction{}
	ZREMRANGEBYSCORE.Cmd = "ZREMRANGEBYSCORE"
	ZREMRANGEBYSCORE.Args = []interface{}{keyName, "-inf", onePeriodAgo.UnixNano()}

	ZRANGE := rediscluster.ClusterTransaction{}
	ZRANGE.Cmd = "ZRANGE"
	ZRANGE.Args = []interface{}{keyName, 0, -1}

	var redVal []interface{}
	var err error
	if pipeline {
		redVal, err = redis.Values(r.singleton().DoPipeline([]rediscluster.ClusterTransaction{ZREMRANGEBYSCORE, ZRANGE}))
	} else {
		redVal, err = redis.Values(r.singleton().DoTransaction([]rediscluster.ClusterTransaction{ZREMRANGEBYSCORE, ZRANGE}))
	}
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

	r.ensureConnection()
	if _, err := r.singleton().Do("ZADD", fixedKey, score, value); err != nil {
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

	values, err := redis.Strings(r.singleton().Do("ZRANGEBYSCORE", fixedKey, scoreFrom, scoreTo, "WITHSCORES"))
	if err != nil {
		log.WithFields(logEntry).WithError(err).Error("ZRANGEBYSCORE command failed")
		return nil, nil, err
	}

	if len(values) == 0 {
		return nil, nil, nil
	}

	elements := make([]string, len(values)/2)
	scores := make([]float64, len(values)/2)

	for i := 0; i < len(elements); i++ {
		elements[i] = values[i*2]
		scores[i], _ = strconv.ParseFloat(values[i*2+1], 64)
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

	if _, err := r.singleton().Do("ZREMRANGEBYSCORE", fixedKey, scoreFrom, scoreTo); err != nil {
		log.WithFields(logEntry).WithError(err).Error("ZREMRANGEBYSCORE command failed")
		return err
	}

	return nil
}
