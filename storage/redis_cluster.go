package storage

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"crypto/tls"

	"github.com/go-redis/redis/v8"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/config"
)

// ------------------- REDIS CLUSTER STORAGE MANAGER -------------------------------

const (
	defaultRedisPort = 6379
)

// ErrRedisIsDown is returned when we can't communicate with redis
var ErrRedisIsDown = errors.New("storage: Redis is either down or was not configured")

var singlePool atomic.Value
var singleCachePool atomic.Value
var singleAnalyticsPool atomic.Value

var redisUp atomic.Value

var disableRedis atomic.Value
var ctx = context.Background()

// DisableRedis very handy when testsing it allows to dynamically enable/disable talking with
// redisW
func DisableRedis(ok bool) {
	if ok {
		// we make sure to set that redis is down
		redisUp.Store(false)
		disableRedis.Store(true)
		return
	}

	disableRedis.Store(false)
	WaitConnect(context.Background())
}

func shouldConnect() bool {
	ok := true
	if v := disableRedis.Load(); v != nil {
		ok = !v.(bool)
	}
	return ok
}

// Connected returns true if we are connected to redis
func Connected() bool {
	v := redisUp.Load()
	if v != nil {
		return v.(bool)
	}
	return false
}

func WaitConnect(ctx context.Context) bool {
	for {
		select {
		case <-ctx.Done():
			return false
		default:
			if Connected() {
				return true
			}

			time.Sleep(10 * time.Millisecond)
		}
	}
}

func singleton(cache, analytics bool) redis.UniversalClient {
	if cache {
		v := singleCachePool.Load()
		if v != nil {
			return v.(redis.UniversalClient)
		}
		return nil
	}
	if analytics {
		v := singleAnalyticsPool.Load()
		if v != nil {
			return v.(redis.UniversalClient)
		}
		return nil
	}
	v := singlePool.Load()
	if v != nil {
		return v.(redis.UniversalClient)
	}
	return nil
}

func connectSingleton(cache, analytics bool) bool {
	d := singleton(cache, analytics) == nil
	if d {
		log.Debug("Connecting to redis cluster")
		if cache {
			singleCachePool.Store(NewRedisClusterPool(cache, analytics))
			return true
		} else if analytics {
			singleAnalyticsPool.Store(NewRedisClusterPool(cache, analytics))
			return true
		}
		singlePool.Store(NewRedisClusterPool(cache, analytics))
		return true
	}
	return true
}

// RedisCluster is a storage manager that uses the redis database.
type RedisCluster struct {
	KeyPrefix   string
	HashKeys    bool
	IsCache     bool
	IsAnalytics bool
}

func clusterConnectionIsOpen(cluster *RedisCluster) bool {
	c := singleton(cluster.IsCache, cluster.IsAnalytics)
	testKey := "redis-test-" + uuid.NewV4().String()
	if err := c.Set(ctx, testKey, "test", time.Second).Err(); err != nil {
		return false
	}
	if _, err := c.Get(ctx, testKey).Result(); err != nil {
		return false
	}
	return true
}

// ConnectToRedis starts a go routine that periodically tries to connect to
// redis.
//
// onConnect will be called when we have established a successful redis connection
func ConnectToRedis(ctx context.Context, onConnect func()) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	c := []RedisCluster{
		{}, {IsCache: true}, {IsAnalytics: true},
	}
	var ok bool
	for _, v := range c {
		if !connectSingleton(v.IsCache, v.IsAnalytics) {
			break
		}
		if !clusterConnectionIsOpen(&v) {
			redisUp.Store(false)
			break
		}
		ok = true
	}
	redisUp.Store(ok)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if !shouldConnect() {
				continue
			}
			conn := Connected()
			ok := connectCluster(c...)

			redisUp.Store(ok)
			if !conn && ok {
				// Here we are transitioning from DISCONNECTED to CONNECTED state
				if onConnect != nil {
					onConnect()
				}
			}
		}
	}
}

func connectCluster(v ...RedisCluster) bool {
	for _, x := range v {
		if ok := establishConnection(&x); ok {
			return ok
		}
	}
	return false
}

func establishConnection(v *RedisCluster) bool {
	if !connectSingleton(v.IsCache, v.IsAnalytics) {
		return false
	}
	return clusterConnectionIsOpen(v)
}

func NewRedisClusterPool(isCache, isAnalytics bool) redis.UniversalClient {
	// redisSingletonMu is locked and we know the singleton is nil
	cfg := config.Global().Storage
	if isCache && config.Global().EnableSeperateCacheStore {
		cfg = config.Global().CacheStorage
	} else if isAnalytics && config.Global().EnableAnalytics && config.Global().EnableSeperateAnalyticsStore {
		cfg = config.Global().AnalyticsStorage
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

	var tlsConfig *tls.Config

	if cfg.UseSSL {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: cfg.SSLInsecureSkipVerify,
		}
	}

	var client redis.UniversalClient
	opts := &redis.UniversalOptions{
		Addrs:            getRedisAddrs(cfg),
		MasterName:       cfg.MasterName,
		SentinelPassword: cfg.SentinelPassword,
		Username:         cfg.Username,
		Password:         cfg.Password,
		DB:               cfg.Database,
		DialTimeout:      timeout,
		ReadTimeout:      timeout,
		WriteTimeout:     timeout,
		IdleTimeout:      240 * timeout,
		PoolSize:         poolSize,
		TLSConfig:        tlsConfig,
	}

	if opts.MasterName != "" {
		log.Info("--> [REDIS] Creating sentinel-backed failover client")
		client = redis.NewFailoverClient(opts.Failover())
	} else if cfg.EnableCluster {
		log.Info("--> [REDIS] Creating cluster client")
		client = redis.NewClusterClient(opts.Cluster())
	} else {
		log.Info("--> [REDIS] Creating single-node client")
		client = redis.NewClient(opts.Simple())
	}

	return client
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

func (r *RedisCluster) singleton() redis.UniversalClient {
	return singleton(r.IsCache, r.IsAnalytics)
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
	if !Connected() {
		return ErrRedisIsDown
	}
	return nil
}

// GetKey will retrieve a key from the database
func (r *RedisCluster) GetKey(keyName string) (string, error) {
	if err := r.up(); err != nil {
		return "", err
	}
	cluster := r.singleton()

	value, err := cluster.Get(ctx, r.fixKey(keyName)).Result()
	if err != nil {
		log.Debug("Error trying to get value:", err)
		return "", ErrKeyNotFound
	}

	return value, nil
}

// GetMultiKey gets multiple keys from the database
func (r *RedisCluster) GetMultiKey(keys []string) ([]string, error) {
	if err := r.up(); err != nil {
		return nil, err
	}
	cluster := r.singleton()
	keyNames := make([]string, len(keys))
	copy(keyNames, keys)
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
				getCmds = append(getCmds, pipe.Get(ctx, key))
			}
			_, err := pipe.Exec(ctx)
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
			values, err := cluster.MGet(ctx, keyNames...).Result()
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
	if err = r.up(); err != nil {
		return 0, err
	}
	duration, err := r.singleton().TTL(ctx, r.fixKey(keyName)).Result()
	return int64(duration.Seconds()), err
}

func (r *RedisCluster) GetRawKey(keyName string) (string, error) {
	if err := r.up(); err != nil {
		return "", err
	}
	value, err := r.singleton().Get(ctx, keyName).Result()
	if err != nil {
		log.Debug("Error trying to get value:", err)
		return "", ErrKeyNotFound
	}

	return value, nil
}

func (r *RedisCluster) GetExp(keyName string) (int64, error) {
	//	log.Debug("Getting exp for key: ", r.fixKey(keyName))
	if err := r.up(); err != nil {
		return 0, err
	}

	value, err := r.singleton().TTL(ctx, r.fixKey(keyName)).Result()
	if err != nil {
		log.Error("Error trying to get TTL: ", err)
		return 0, ErrKeyNotFound
	}
	//since redis-go v8.3.1, if there's no expiration or the key doesn't exists, the ttl returned is measured in nanoseconds
	if value.Nanoseconds() == -1 || value.Nanoseconds() == -2 {
		return value.Nanoseconds(), nil
	}

	return int64(value.Seconds()), nil
}

func (r *RedisCluster) SetExp(keyName string, timeout int64) error {
	if err := r.up(); err != nil {
		return err
	}
	err := r.singleton().Expire(ctx, r.fixKey(keyName), time.Duration(timeout)*time.Second).Err()
	if err != nil {
		log.Error("Could not EXPIRE key: ", err)
	}
	return err
}

// SetKey will create (or update) a key value in the store
func (r *RedisCluster) SetKey(keyName, session string, timeout int64) error {
	//log.Debug("[STORE] SET Raw key is: ", keyName)
	//log.Debug("[STORE] Setting key: ", r.fixKey(keyName))

	if err := r.up(); err != nil {
		return err
	}
	err := r.singleton().Set(ctx, r.fixKey(keyName), session, time.Duration(timeout)*time.Second).Err()
	if err != nil {
		log.Error("Error trying to set value: ", err)
		return err
	}
	return nil
}

func (r *RedisCluster) SetRawKey(keyName, session string, timeout int64) error {
	if err := r.up(); err != nil {
		return err
	}
	err := r.singleton().Set(ctx, keyName, session, time.Duration(timeout)*time.Second).Err()
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
	if err := r.up(); err != nil {
		log.Debug(err)
		return
	}
	err := r.singleton().Decr(ctx, keyName).Err()
	if err != nil {
		log.Error("Error trying to decrement value:", err)
	}
}

// IncrementWithExpire will increment a key in redis
func (r *RedisCluster) IncrememntWithExpire(keyName string, expire int64) int64 {
	// log.Debug("Incrementing raw key: ", keyName)
	if err := r.up(); err != nil {
		log.Debug(err)
		return 0
	}
	// This function uses a raw key, so we shouldn't call fixKey
	fixedKey := keyName
	val, err := r.singleton().Incr(ctx, fixedKey).Result()

	if err != nil {
		log.Error("Error trying to increment value:", err)
	} else {
		log.Debug("Incremented key: ", fixedKey, ", val is: ", val)
	}

	if val == 1 && expire > 0 {
		log.Debug("--> Setting Expire")
		r.singleton().Expire(ctx, fixedKey, time.Duration(expire)*time.Second)
	}

	return val
}

// GetKeys will return all keys according to the filter (filter is a prefix - e.g. tyk.keys.*)
func (r *RedisCluster) GetKeys(filter string) []string {
	if err := r.up(); err != nil {
		log.Debug(err)
		return nil
	}
	client := r.singleton()

	filterHash := ""
	if filter != "" {
		filterHash = r.hashKey(filter)
	}
	searchStr := r.KeyPrefix + filterHash + "*"
	log.Debug("[STORE] Getting list by: ", searchStr)

	fnFetchKeys := func(client *redis.Client) ([]string, error) {
		values := make([]string, 0)

		iter := client.Scan(ctx, 0, searchStr, 0).Iterator()
		for iter.Next(ctx) {
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
			err = v.ForEachMaster(ctx, func(ctx context.Context, client *redis.Client) error {
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
	if err := r.up(); err != nil {
		log.Debug(err)
		return nil
	}
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
				getCmds = append(getCmds, pipe.Get(ctx, key))
			}
			_, err := pipe.Exec(ctx)
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
			result, err := v.MGet(ctx, keys...).Result()
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
	if err := r.up(); err != nil {
		log.Debug(err)
		return false
	}
	log.Debug("DEL Key was: ", keyName)
	log.Debug("DEL Key became: ", r.fixKey(keyName))
	n, err := r.singleton().Del(ctx, r.fixKey(keyName)).Result()
	if err != nil {
		log.WithError(err).Error("Error trying to delete key")
	}

	return n > 0
}

// DeleteAllKeys will remove all keys from the database.
func (r *RedisCluster) DeleteAllKeys() bool {
	if err := r.up(); err != nil {
		log.Debug(err)
		return false
	}
	n, err := r.singleton().FlushAll(ctx).Result()
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
	if err := r.up(); err != nil {
		log.Debug(err)
		return false
	}
	n, err := r.singleton().Del(ctx, keyName).Result()
	if err != nil {
		log.WithError(err).Error("Error trying to delete key")
	}

	return n > 0
}

// DeleteKeys will remove a group of keys in bulk
func (r *RedisCluster) DeleteScanMatch(pattern string) bool {
	if err := r.up(); err != nil {
		log.Debug(err)
		return false
	}
	client := r.singleton()
	log.Debug("Deleting: ", pattern)

	fnScan := func(client *redis.Client) ([]string, error) {
		values := make([]string, 0)

		iter := client.Scan(ctx, 0, pattern, 0).Iterator()
		for iter.Next(ctx) {
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
			err = v.ForEachMaster(ctx, func(ctx context.Context, client *redis.Client) error {
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
			err := client.Del(ctx, name).Err()
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
	if err := r.up(); err != nil {
		log.Debug(err)
		return false
	}
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
					pipe.Del(ctx, k)
				}

				if _, err := pipe.Exec(ctx); err != nil {
					log.Error("Error trying to delete keys:", err)
				}
			}
		case *redis.Client:
			{
				_, err := v.Del(ctx, keys...).Result()
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
		msg, err := pubsub.Receive(ctx)
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
	if err := r.up(); err != nil {
		return err
	}
	err := r.singleton().Publish(ctx, channel, message).Err()
	if err != nil {
		log.Error("Error trying to set value: ", err)
		return err
	}
	return nil
}

func (r *RedisCluster) GetAndDeleteSet(keyName string) []interface{} {
	log.Debug("Getting raw key set: ", keyName)
	if err := r.up(); err != nil {
		log.Debug(err)
		return nil
	}
	log.Debug("keyName is: ", keyName)
	fixedKey := r.fixKey(keyName)
	log.Debug("Fixed keyname is: ", fixedKey)

	client := r.singleton()

	var lrange *redis.StringSliceCmd
	_, err := client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		lrange = pipe.LRange(ctx, fixedKey, 0, -1)
		pipe.Del(ctx, fixedKey)
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
	if err := r.up(); err != nil {
		log.Debug(err)
		return
	}
	if err := r.singleton().RPush(ctx, fixedKey, value).Err(); err != nil {
		log.WithError(err).Error("Error trying to append to set keys")
	}
}

//Exists check if keyName exists
func (r *RedisCluster) Exists(keyName string) (bool, error) {
	fixedKey := r.fixKey(keyName)
	log.WithField("keyName", fixedKey).Debug("Checking if exists")

	exists, err := r.singleton().Exists(ctx, fixedKey).Result()
	if err != nil {
		log.Error("Error trying to check if key exists: ", err)
		return false, err
	}
	if exists == 1 {
		return true, nil
	}
	return false, nil
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

	if err := r.singleton().LRem(ctx, fixedKey, 0, value).Err(); err != nil {
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

	elements, err := r.singleton().LRange(ctx, fixedKey, from, to).Result()
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
	if err := r.up(); err != nil {
		log.Debug(err)
		return
	}
	client := r.singleton()

	pipe := client.Pipeline()
	for _, val := range values {
		pipe.RPush(ctx, fixedKey, val)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		log.WithError(err).Error("Error trying to append to set keys")
	}
}

func (r *RedisCluster) GetSet(keyName string) (map[string]string, error) {
	log.Debug("Getting from key set: ", keyName)
	log.Debug("Getting from fixed key set: ", r.fixKey(keyName))
	if err := r.up(); err != nil {
		return nil, err
	}
	val, err := r.singleton().SMembers(ctx, r.fixKey(keyName)).Result()
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
	if err := r.up(); err != nil {
		log.Debug(err)
		return
	}
	err := r.singleton().SAdd(ctx, r.fixKey(keyName), value).Err()
	if err != nil {
		log.Error("Error trying to append keys: ", err)
	}
}

func (r *RedisCluster) RemoveFromSet(keyName, value string) {
	log.Debug("Removing from raw key set: ", keyName)
	log.Debug("Removing from fixed key set: ", r.fixKey(keyName))
	if err := r.up(); err != nil {
		log.Debug(err)
		return
	}
	err := r.singleton().SRem(ctx, r.fixKey(keyName), value).Err()
	if err != nil {
		log.Error("Error trying to remove keys: ", err)
	}
}

func (r *RedisCluster) IsMemberOfSet(keyName, value string) bool {
	if err := r.up(); err != nil {
		log.Debug(err)
		return false
	}
	val, err := r.singleton().SIsMember(ctx, r.fixKey(keyName), value).Result()

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
	if err := r.up(); err != nil {
		log.Debug(err)
		return 0, nil
	}
	log.Debug("keyName is: ", keyName)
	now := time.Now()
	log.Debug("Now is:", now)
	onePeriodAgo := now.Add(time.Duration(-1*per) * time.Second)
	log.Debug("Then is: ", onePeriodAgo)

	client := r.singleton()
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

		pipe.ZAdd(ctx, keyName, &element)
		pipe.Expire(ctx, keyName, time.Duration(per)*time.Second)

		return nil
	}

	var err error
	if pipeline {
		_, err = client.Pipelined(ctx, pipeFn)
	} else {
		_, err = client.TxPipelined(ctx, pipeFn)
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
	if err := r.up(); err != nil {
		log.Debug(err)
		return 0, nil
	}
	now := time.Now()
	onePeriodAgo := now.Add(time.Duration(-1*per) * time.Second)

	client := r.singleton()
	var zrange *redis.StringSliceCmd

	pipeFn := func(pipe redis.Pipeliner) error {
		pipe.ZRemRangeByScore(ctx, keyName, "-inf", strconv.Itoa(int(onePeriodAgo.UnixNano())))
		zrange = pipe.ZRange(ctx, keyName, 0, -1)

		return nil
	}

	var err error
	if pipeline {
		_, err = client.Pipelined(ctx, pipeFn)
	} else {
		_, err = client.TxPipelined(ctx, pipeFn)
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

	if err := r.up(); err != nil {
		log.Debug(err)
		return
	}
	member := redis.Z{Score: score, Member: value}
	if err := r.singleton().ZAdd(ctx, fixedKey, &member).Err(); err != nil {
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
	values, err := r.singleton().ZRangeByScoreWithScores(ctx, fixedKey, &args).Result()
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

	if err := r.singleton().ZRemRangeByScore(ctx, fixedKey, scoreFrom, scoreTo).Err(); err != nil {
		log.WithFields(logEntry).WithError(err).Error("ZREMRANGEBYSCORE command failed")
		return err
	}

	return nil
}
