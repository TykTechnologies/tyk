package storage

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"crypto/tls"

	"github.com/go-redis/redis"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"

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

	redisClusterSingleton      redis.UniversalClient
	redisCacheClusterSingleton redis.UniversalClient
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

func NewRedisClusterPool(isCache bool) redis.UniversalClient {
	// redisSingletonMu is locked and we know the singleton is nil
	cfg := config.Global().Storage
	if isCache && config.Global().EnableSeperateCacheStore {
		cfg = config.Global().CacheStorage
	}

	log.Debug("Creating new Redis connection pool")

	// poolSize applies per cluster node and not for the whole cluster.
	poolSize := 500
	if cfg.MaxActive > 0 {
		poolSize = cfg.MaxActive
	}

	timeout := 5 * time.Second

	if cfg.Timeout > 0 {
		timeout = time.Duration(cfg.Timeout) * time.Second
	}

	if cfg.Port == 0 {
		cfg.Port = defaultRedisPort
	}

	var seedHosts []string

	if len(cfg.Addrs) != 0 {
		seedHosts = cfg.Addrs
	} else {
		for h, p := range cfg.Hosts {
			addr := h + ":" + p
			seedHosts = append(seedHosts, addr)
		}
	}

	if len(seedHosts) == 0 {
		addr := cfg.Host + ":" + strconv.Itoa(cfg.Port)
		seedHosts = append(seedHosts, addr)
	}

	var tlsConfig *tls.Config

	if cfg.UseSSL {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: cfg.SSLInsecureSkipVerify,
		}
	}

	var client redis.UniversalClient
	opts := &RedisOpts{
		Addrs:        seedHosts,
		Password:     cfg.Password,
		DB:           cfg.Database,
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
		IdleTimeout:  240 * timeout,
		PoolSize:     poolSize,
		TLSConfig:    tlsConfig,
	}

	if cfg.EnableCluster {
		log.Info("--> [REDIS] Using clustered mode")
		client = redis.NewClusterClient(opts.cluster())
	} else {
		log.Info("--> [REDIS] Using single node mode")
		client = redis.NewClient(opts.simple())
	}

	return client
}

// RedisOpts is the overriden type of redis.UniversalOptions. simple() and cluster() functions are not public
// in redis library. Therefore, they are redefined in here to use in creation of new redis cluster logic.
// We don't want to use redis.NewUniversalClient() logic.
type RedisOpts redis.UniversalOptions

func (o *RedisOpts) cluster() *redis.ClusterOptions {
	if len(o.Addrs) == 0 {
		o.Addrs = []string{"127.0.0.1:6379"}
	}

	return &redis.ClusterOptions{
		Addrs:     o.Addrs,
		OnConnect: o.OnConnect,

		Password: o.Password,

		MaxRedirects:   o.MaxRedirects,
		ReadOnly:       o.ReadOnly,
		RouteByLatency: o.RouteByLatency,
		RouteRandomly:  o.RouteRandomly,

		MaxRetries:      o.MaxRetries,
		MinRetryBackoff: o.MinRetryBackoff,
		MaxRetryBackoff: o.MaxRetryBackoff,

		DialTimeout:        o.DialTimeout,
		ReadTimeout:        o.ReadTimeout,
		WriteTimeout:       o.WriteTimeout,
		PoolSize:           o.PoolSize,
		MinIdleConns:       o.MinIdleConns,
		MaxConnAge:         o.MaxConnAge,
		PoolTimeout:        o.PoolTimeout,
		IdleTimeout:        o.IdleTimeout,
		IdleCheckFrequency: o.IdleCheckFrequency,

		TLSConfig: o.TLSConfig,
	}
}

func (o *RedisOpts) simple() *redis.Options {
	addr := "127.0.0.1:6379"
	if len(o.Addrs) > 0 {
		addr = o.Addrs[0]
	}

	return &redis.Options{
		Addr:      addr,
		OnConnect: o.OnConnect,

		DB:       o.DB,
		Password: o.Password,

		MaxRetries:      o.MaxRetries,
		MinRetryBackoff: o.MinRetryBackoff,
		MaxRetryBackoff: o.MaxRetryBackoff,

		DialTimeout:  o.DialTimeout,
		ReadTimeout:  o.ReadTimeout,
		WriteTimeout: o.WriteTimeout,

		PoolSize:           o.PoolSize,
		MinIdleConns:       o.MinIdleConns,
		MaxConnAge:         o.MaxConnAge,
		PoolTimeout:        o.PoolTimeout,
		IdleTimeout:        o.IdleTimeout,
		IdleCheckFrequency: o.IdleCheckFrequency,

		TLSConfig: o.TLSConfig,
	}
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

func (r *RedisCluster) singleton() redis.UniversalClient {
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
	// log.Debug("[STORE] Getting WAS: ", keyName)
	// log.Debug("[STORE] Getting: ", r.fixKey(keyName))
	cluster := r.singleton()

	value, err := cluster.Get(r.fixKey(keyName)).Result()
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

	for index, val := range keyNames {
		keyNames[index] = r.fixKey(val)
	}

	result := make([]string, 0)

	switch v := cluster.(type) {
	case *redis.ClusterClient:
		{
			getCmds := make([]*redis.StringCmd, 0)
			pipe := v.Pipeline()
			for _, key := range keyNames {
				getCmds = append(getCmds, pipe.Get(key))
			}
			_, err := pipe.Exec()
			if err != nil && err != redis.Nil {
				log.WithError(err).Debug("Error trying to get value")
				return nil, ErrKeyNotFound
			}
			for _, cmd := range getCmds {
				result = append(result, cmd.Val())
			}
		}
	case *redis.Client:
		{
			values, err := cluster.MGet(keyNames...).Result()
			if err != nil {
				log.WithError(err).Debug("Error trying to get value")
				return nil, ErrKeyNotFound
			}
			for _, val := range values {
				strVal := fmt.Sprint(val)
				if strVal == "<nil>" {
					strVal = ""
				}
				result = append(result, strVal)
			}
		}
	}

	for _, val := range result {
		if val != "" {
			return result, nil
		}
	}

	return nil, ErrKeyNotFound
}

func (r *RedisCluster) GetKeyTTL(keyName string) (ttl int64, err error) {
	r.ensureConnection()
	duration, err := r.singleton().TTL(r.fixKey(keyName)).Result()
	return int64(duration.Seconds()), err
}

func (r *RedisCluster) GetRawKey(keyName string) (string, error) {
	r.ensureConnection()
	value, err := r.singleton().Get(keyName).Result()
	if err != nil {
		log.Debug("Error trying to get value:", err)
		return "", ErrKeyNotFound
	}

	return value, nil
}

func (r *RedisCluster) GetExp(keyName string) (int64, error) {
	//	log.Debug("Getting exp for key: ", r.fixKey(keyName))
	r.ensureConnection()

	value, err := r.singleton().TTL(r.fixKey(keyName)).Result()
	if err != nil {
		log.Error("Error trying to get TTL: ", err)
		return 0, ErrKeyNotFound
	}
	return int64(value.Seconds()), nil
}

func (r *RedisCluster) SetExp(keyName string, timeout int64) error {
	err := r.singleton().Expire(r.fixKey(keyName), time.Duration(timeout)*time.Second).Err()
	if err != nil {
		log.Error("Could not EXPIRE key: ", err)
	}
	return err
}

// SetKey will create (or update) a key value in the store
func (r *RedisCluster) SetKey(keyName, session string, timeout int64) error {
	//log.Debug("[STORE] SET Raw key is: ", keyName)
	//log.Debug("[STORE] Setting key: ", r.fixKey(keyName))

	r.ensureConnection()
	err := r.singleton().Set(r.fixKey(keyName), session, 0).Err()
	if err != nil {
		log.Error("Error trying to set value: ", err)
		return err
	}

	if timeout > 0 {
		err := r.singleton().Expire(r.fixKey(keyName), time.Duration(timeout)*time.Second).Err()
		if err != nil {
			log.Error("Error trying to set expiry:", err)
			return err
		}
	}

	return nil
}

func (r *RedisCluster) SetRawKey(keyName, session string, timeout int64) error {
	r.ensureConnection()
	err := r.singleton().Set(keyName, session, time.Duration(timeout)*time.Second).Err()
	if err != nil {
		log.Error("Error trying to set value: ", err)
		return err
	}
	return nil
}

// Decrement will decrement a key in redis
func (r *RedisCluster) Decrement(keyName string) {
	keyName = r.fixKey(keyName)
	// log.Debug("Decrementing key: ", keyName)
	r.ensureConnection()
	err := r.singleton().Decr(keyName).Err()
	if err != nil {
		log.Error("Error trying to decrement value:", err)
	}
}

// IncrementWithExpire will increment a key in redis
func (r *RedisCluster) IncrememntWithExpire(keyName string, expire int64) int64 {
	// log.Debug("Incrementing raw key: ", keyName)
	r.ensureConnection()

	// This function uses a raw key, so we shouldn't call fixKey
	fixedKey := keyName
	val, err := r.singleton().Incr(fixedKey).Result()

	if err != nil {
		log.Error("Error trying to increment value:", err)
	} else {
		log.Debug("Incremented key: ", fixedKey, ", val is: ", val)
	}

	if val == 1 && expire != 0 {
		log.Debug("--> Setting Expire")
		r.singleton().Expire(fixedKey, time.Duration(expire)*time.Second)
	}

	return val
}

// GetKeys will return all keys according to the filter (filter is a prefix - e.g. tyk.keys.*)
func (r *RedisCluster) GetKeys(filter string) []string {
	r.ensureConnection()
	client := r.singleton()

	filterHash := ""
	if filter != "" {
		filterHash = r.hashKey(filter)
	}
	searchStr := r.KeyPrefix + filterHash + "*"
	log.Debug("[STORE] Getting list by: ", searchStr)

	fnFetchKeys := func(client *redis.Client) ([]string, error) {
		values := make([]string, 0)

		iter := client.Scan(0, searchStr, 0).Iterator()
		for iter.Next() {
			values = append(values, iter.Val())
		}

		if err := iter.Err(); err != nil {
			return nil, err
		}

		return values, nil
	}

	var err error
	sessions := make([]string, 0)

	switch v := client.(type) {
	case *redis.ClusterClient:
		ch := make(chan []string)

		go func() {
			err = v.ForEachMaster(func(client *redis.Client) error {
				values, err := fnFetchKeys(client)
				if err != nil {
					return err
				}

				ch <- values
				return nil
			})
			close(ch)
		}()

		for res := range ch {
			sessions = append(sessions, res...)
		}
	case *redis.Client:
		sessions, err = fnFetchKeys(v)
	}

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
	r.ensureConnection()
	keys := r.GetKeys(filter)
	if keys == nil {
		log.Error("Error trying to get filtered client keys")
		return nil
	}

	if len(keys) == 0 {
		return nil
	}

	for i, v := range keys {
		keys[i] = r.KeyPrefix + v
	}

	client := r.singleton()
	values := make([]string, 0)

	switch v := client.(type) {
	case *redis.ClusterClient:
		{
			getCmds := make([]*redis.StringCmd, 0)
			pipe := v.Pipeline()
			for _, key := range keys {
				getCmds = append(getCmds, pipe.Get(key))
			}
			_, err := pipe.Exec()
			if err != nil && err != redis.Nil {
				log.Error("Error trying to get client keys: ", err)
				return nil
			}

			for _, cmd := range getCmds {
				values = append(values, cmd.Val())
			}
		}
	case *redis.Client:
		{
			result, err := v.MGet(keys...).Result()
			if err != nil {
				log.Error("Error trying to get client keys: ", err)
				return nil
			}

			for _, val := range result {
				strVal := fmt.Sprint(val)
				if strVal == "<nil>" {
					strVal = ""
				}
				values = append(values, strVal)
			}
		}
	}

	m := make(map[string]string)
	for i, v := range keys {
		m[r.cleanKey(v)] = values[i]

	}

	return m
}

// GetKeysAndValues will return all keys and their values - not to be used lightly
func (r *RedisCluster) GetKeysAndValues() map[string]string {
	return r.GetKeysAndValuesWithFilter("")
}

// DeleteKey will remove a key from the database
func (r *RedisCluster) DeleteKey(keyName string) bool {
	r.ensureConnection()
	log.Debug("DEL Key was: ", keyName)
	log.Debug("DEL Key became: ", r.fixKey(keyName))
	n, err := r.singleton().Del(r.fixKey(keyName)).Result()
	if err != nil {
		log.WithError(err).Error("Error trying to delete key")
	}

	return n > 0
}

// DeleteAllKeys will remove all keys from the database.
func (r *RedisCluster) DeleteAllKeys() bool {
	r.ensureConnection()
	n, err := r.singleton().FlushAll().Result()
	if err != nil {
		log.WithError(err).Error("Error trying to delete keys")
	}

	if n == "OK" {
		return true
	}

	return false
}

// DeleteKey will remove a key from the database without prefixing, assumes user knows what they are doing
func (r *RedisCluster) DeleteRawKey(keyName string) bool {
	r.ensureConnection()
	n, err := r.singleton().Del(keyName).Result()
	if err != nil {
		log.WithError(err).Error("Error trying to delete key")
	}

	return n > 0
}

// DeleteKeys will remove a group of keys in bulk
func (r *RedisCluster) DeleteScanMatch(pattern string) bool {
	r.ensureConnection()
	client := r.singleton()
	log.Debug("Deleting: ", pattern)

	fnScan := func(client *redis.Client) ([]string, error) {
		values := make([]string, 0)

		iter := client.Scan(0, pattern, 0).Iterator()
		for iter.Next() {
			values = append(values, iter.Val())
		}

		if err := iter.Err(); err != nil {
			return nil, err
		}

		return values, nil
	}

	var err error
	var keys []string

	switch v := client.(type) {
	case *redis.ClusterClient:
		ch := make(chan []string)
		go func() {
			err = v.ForEachMaster(func(client *redis.Client) error {
				values, err := fnScan(client)
				if err != nil {
					return err
				}

				ch <- values
				return nil
			})
			close(ch)
		}()

		for vals := range ch {
			keys = append(keys, vals...)
		}
	case *redis.Client:
		keys, err = fnScan(v)
	}

	if err != nil {
		log.Error("SCAN command field with err:", err)
		return false
	}

	if len(keys) > 0 {
		for _, name := range keys {
			log.Info("Deleting: ", name)
			err := client.Del(name).Err()
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
		for i, v := range keys {
			keys[i] = r.fixKey(v)
		}

		log.Debug("Deleting: ", keys)
		client := r.singleton()
		switch v := client.(type) {
		case *redis.ClusterClient:
			{
				pipe := v.Pipeline()
				for _, k := range keys {
					pipe.Del(k)
				}

				if _, err := pipe.Exec(); err != nil {
					log.Error("Error trying to delete keys:", err)
				}
			}
		case *redis.Client:
			{
				_, err := v.Del(keys...).Result()
				if err != nil {
					log.Error("Error trying to delete keys: ", err)
				}
			}
		}
	} else {
		log.Debug("RedisCluster called DEL - Nothing to delete")
	}

	return true
}

// StartPubSubHandler will listen for a signal and run the callback for
// every subscription and message event.
func (r *RedisCluster) StartPubSubHandler(channel string, callback func(interface{})) error {
	r.ensureConnection()
	client := r.singleton()
	if client == nil {
		return errors.New("Redis connection failed")
	}

	pubsub := client.Subscribe(channel)
	defer pubsub.Close()

	for {
		msg, err := pubsub.Receive()
		if err != nil {
			log.Error("Error while receiving pubsub message:", err)
			return err
		}
		switch v := msg.(type) {
		case *redis.Message:
			callback(v)

		case *redis.Subscription:
			callback(v)

		case error:
			log.Error("Redis disconnected or error received, attempting to reconnect: ", v)
			return v
		}
	}
}

func (r *RedisCluster) Publish(channel, message string) error {
	r.ensureConnection()
	err := r.singleton().Publish(channel, message).Err()
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

	client := r.singleton()

	var lrange *redis.StringSliceCmd
	_, err := client.TxPipelined(func(pipe redis.Pipeliner) error {
		lrange = pipe.LRange(fixedKey, 0, -1)
		pipe.Del(fixedKey)
		return nil
	})
	if err != nil {
		log.Error("Multi command failed: ", err)
		return nil
	}

	vals := lrange.Val()
	log.Debug("Analytics returned: ", len(vals))
	if len(vals) == 0 {
		return nil
	}

	log.Debug("Unpacked vals: ", len(vals))
	result := make([]interface{}, len(vals))
	for i, v := range vals {
		result[i] = v
	}

	return result
}

func (r *RedisCluster) AppendToSet(keyName, value string) {
	fixedKey := r.fixKey(keyName)
	log.WithField("keyName", keyName).Debug("Pushing to raw key list")
	log.WithField("fixedKey", fixedKey).Debug("Appending to fixed key list")

	r.ensureConnection()
	if err := r.singleton().RPush(fixedKey, value).Err(); err != nil {
		log.WithError(err).Error("Error trying to append to set keys")
	}
}

func (r *RedisCluster) AppendToSetPipelined(key string, values [][]byte) {
	if len(values) == 0 {
		return
	}

	fixedKey := r.fixKey(key)
	r.ensureConnection()
	client := r.singleton()

	pipe := client.Pipeline()
	for _, val := range values {
		pipe.RPush(fixedKey, val)
	}

	if _, err := pipe.Exec(); err != nil {
		log.WithError(err).Error("Error trying to append to set keys")
	}
}

func (r *RedisCluster) GetSet(keyName string) (map[string]string, error) {
	log.Debug("Getting from key set: ", keyName)
	log.Debug("Getting from fixed key set: ", r.fixKey(keyName))
	r.ensureConnection()

	val, err := r.singleton().SMembers(r.fixKey(keyName)).Result()
	if err != nil {
		log.Error("Error trying to get key set:", err)
		return nil, err
	}

	result := make(map[string]string)
	for i, value := range val {
		result[strconv.Itoa(i)] = value
	}

	return result, nil
}

func (r *RedisCluster) AddToSet(keyName, value string) {
	log.Debug("Pushing to raw key set: ", keyName)
	log.Debug("Pushing to fixed key set: ", r.fixKey(keyName))
	r.ensureConnection()
	err := r.singleton().SAdd(r.fixKey(keyName), value).Err()
	if err != nil {
		log.Error("Error trying to append keys: ", err)
	}
}

func (r *RedisCluster) RemoveFromSet(keyName, value string) {
	log.Debug("Removing from raw key set: ", keyName)
	log.Debug("Removing from fixed key set: ", r.fixKey(keyName))
	r.ensureConnection()

	err := r.singleton().SRem(r.fixKey(keyName), value).Err()
	if err != nil {
		log.Error("Error trying to remove keys: ", err)
	}
}

func (r *RedisCluster) IsMemberOfSet(keyName, value string) bool {
	r.ensureConnection()
	val, err := r.singleton().SIsMember(r.fixKey(keyName), value).Result()

	if err != nil {
		log.Error("Error trying to check set memeber: ", err)
		return false
	}

	log.Debug("SISMEMBER", keyName, value, val, err)

	return val == true
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

	client := r.singleton()
	var zrange *redis.StringSliceCmd

	pipeFn := func(pipe redis.Pipeliner) error {
		pipe.ZRemRangeByScore(keyName, "-inf", strconv.Itoa(int(onePeriodAgo.UnixNano())))
		zrange = pipe.ZRange(keyName, 0, -1)

		element := redis.Z{
			Score: float64(now.UnixNano()),
		}

		if value_override != "-1" {
			element.Member = value_override
		} else {
			element.Member = strconv.Itoa(int(now.UnixNano()))
		}

		pipe.ZAdd(keyName, element)
		pipe.Expire(keyName, time.Duration(per)*time.Second)

		return nil
	}

	var err error
	if pipeline {
		_, err = client.Pipelined(pipeFn)
	} else {
		_, err = client.TxPipelined(pipeFn)
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

func (r RedisCluster) GetRollingWindow(keyName string, per int64, pipeline bool) (int, []interface{}) {
	r.ensureConnection()
	now := time.Now()
	onePeriodAgo := now.Add(time.Duration(-1*per) * time.Second)

	client := r.singleton()
	var zrange *redis.StringSliceCmd

	pipeFn := func(pipe redis.Pipeliner) error {
		pipe.ZRemRangeByScore(keyName, "-inf", strconv.Itoa(int(onePeriodAgo.UnixNano())))
		zrange = pipe.ZRange(keyName, 0, -1)

		return nil
	}

	var err error
	if pipeline {
		_, err = client.Pipelined(pipeFn)
	} else {
		_, err = client.TxPipelined(pipeFn)
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

	r.ensureConnection()
	member := redis.Z{Score: score, Member: value}
	if err := r.singleton().ZAdd(fixedKey, member).Err(); err != nil {
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

	args := redis.ZRangeBy{Min: scoreFrom, Max: scoreTo}
	values, err := r.singleton().ZRangeByScoreWithScores(fixedKey, args).Result()
	if err != nil {
		log.WithFields(logEntry).WithError(err).Error("ZRANGEBYSCORE command failed")
		return nil, nil, err
	}

	if len(values) == 0 {
		return nil, nil, nil
	}

	elements := make([]string, len(values))
	scores := make([]float64, len(values))

	for i, v := range values {
		elements[i] = fmt.Sprint(v.Member)
		scores[i] = v.Score
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

	if err := r.singleton().ZRemRangeByScore(fixedKey, scoreFrom, scoreTo).Err(); err != nil {
		log.WithFields(logEntry).WithError(err).Error("ZREMRANGEBYSCORE command failed")
		return err
	}

	return nil
}
