package storage

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/config"

	"github.com/TykTechnologies/tyk/internal/uuid"
)
...
func (r *RedisCluster) ControllerInitiated() bool {
	return r.RedisController != nil
}
	defaultRedisPort = 6379
)
...
// ErrRedisIsDown is returned when we can't communicate with redis
var ErrRedisIsDown = errors.New("storage: Redis is either down or was not configured")
...
// RedisCluster is a storage manager that uses the redis database.
type RedisCluster struct {
	KeyPrefix   string
	HashKeys    bool
	IsCache     bool
	IsAnalytics bool
	// RedisController must be passed from the gateway
	RedisController *RedisController
}

func NewRedisClusterPool(isCache, isAnalytics bool, conf config.Config) redis.UniversalClient {
	// redisSingletonMu is locked and we know the singleton is nil
	cfg := conf.Storage
	if isCache && conf.EnableSeperateCacheStore {
		cfg = conf.CacheStorage
	} else if isAnalytics && conf.EnableAnalytics && conf.EnableSeperateAnalyticsStore {
		cfg = conf.AnalyticsStorage
	}
	log.Debug("Creating new Redis connection pool")

	// Log the host Tyk is attempting to connect to
	log.Debug("Attempting to connect to Redis host: ", cfg.Host)

...
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
...
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

func clusterConnectionIsOpen(cluster *RedisCluster) bool {
	c := cluster.RedisController.singleton(cluster.IsCache, cluster.IsAnalytics)
	if c == nil {
		return false
	}
	testKey := "redis-test-" + uuid.New()
	if err := c.Set(cluster.RedisController.ctx, testKey, "test", time.Second).Err(); err != nil {
		return false
	}
	if _, err := c.Get(cluster.RedisController.ctx, testKey).Result(); err != nil {
		return false
	}
	return true
}

// Connect will establish a connection this is always true because we are
// dynamically using redis
func (r *RedisCluster) Connect() bool {
	return true
}

func (r *RedisCluster) singleton() (redis.UniversalClient, error) {
	if r.RedisController == nil {
		log.Error("RedisController is nil")
		return nil, fmt.Errorf("Error trying to get singleton instance: RedisController is nil")
	}
	instance := r.RedisController.singleton(r.IsCache, r.IsAnalytics)
	if instance == nil {
		// Log the hostname Tyk is attempting to connect to
		log.Error("Attempting to connect to Redis host: ", r.RedisController.cfg.Host)
		// Log whether the hostname failed to resolve, if the TCP request timed out, if Redis prompted for a password, if Redis responded with `WRONGPASS`, and if SSL failed
		log.Error("Error getting singleton instance: %s. Please check for issues with hostname resolution, TCP timeout, Redis password prompt, WRONGPASS response from Redis, or SSL failure.", ErrRedisIsDown)
		return nil, fmt.Errorf("Error getting singleton instance: %s. Please check for issues with hostname resolution, TCP timeout, Redis password prompt, WRONGPASS response from Redis, or SSL failure.", ErrRedisIsDown)
	}
	return instance, nil
}

// checkIsOpen checks if the connection is open. This method is using for backoff retry.
func (r *RedisCluster) checkIsOpen() error {
	isOpen := clusterConnectionIsOpen(r)
	if !isOpen {
		return ErrRedisIsDown
	}
	return nil
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
	if !r.RedisController.Connected() {
		log.Error("Redis server is not available")
		return ErrRedisIsDown
	}
	return nil
}

// GetKey will retrieve a key from the database
func (r *RedisCluster) GetKey(keyName string) (string, error) {
	if err := r.up(); err != nil {
		return "", err
	}
	singleton, err := r.singleton()
	if err != nil {
		log.Error(err)
		return "", err
	}

	value, err := singleton.Get(r.RedisController.ctx, r.fixKey(keyName)).Result()
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

	cluster, err := r.singleton()
	if err != nil {
		return nil, err
	}

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
				getCmds = append(getCmds, pipe.Get(r.RedisController.ctx, key))
			}
			_, err := pipe.Exec(r.RedisController.ctx)
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
			values, err := cluster.MGet(r.RedisController.ctx, keyNames...).Result()
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

	singleton, err := r.singleton()
	if err != nil {
		return 0, err
	}

	duration, err := singleton.TTL(r.RedisController.ctx, r.fixKey(keyName)).Result()
	return int64(duration.Seconds()), err
}

func (r *RedisCluster) GetRawKey(keyName string) (string, error) {
	if err := r.up(); err != nil {
		return "", err
	}

	singleton, err := r.singleton()
	if err != nil {
		return "", err
	}

	value, err := singleton.Get(r.RedisController.ctx, keyName).Result()
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

	singleton, err := r.singleton()
	if err != nil {
		return 0, err
	}

	value, err := singleton.TTL(r.RedisController.ctx, r.fixKey(keyName)).Result()
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

	singleton, err := r.singleton()
	if err != nil {
		return err
	}

	err = singleton.Expire(r.RedisController.ctx, r.fixKey(keyName), time.Duration(timeout)*time.Second).Err()
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

	singleton, err := r.singleton()
	if err != nil {
		return err
	}

	err = singleton.Set(r.RedisController.ctx, r.fixKey(keyName), session, time.Duration(timeout)*time.Second).Err()
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

	singleton, err := r.singleton()
	if err != nil {
		return err
	}

	err = singleton.Set(r.RedisController.ctx, keyName, session, time.Duration(timeout)*time.Second).Err()
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

	singleton, err := r.singleton()
	if err != nil {
		log.Error(err)
		return
	}

	err = singleton.Decr(r.RedisController.ctx, keyName).Err()
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

	singleton, err := r.singleton()
	if err != nil {
		log.Error(err)
		return 0
	}

	val, err := singleton.Incr(r.RedisController.ctx, fixedKey).Result()

	if err != nil {
		log.Error("Error trying to increment value:", err)
	} else {
		log.Debug("Incremented key: ", fixedKey, ", val is: ", val)
	}

	if val == 1 && expire > 0 {
		log.Debug("--> Setting Expire")
		singleton.Expire(r.RedisController.ctx, fixedKey, time.Duration(expire)*time.Second)
	}

	return val
}

// GetKeys will return all keys according to the filter (filter is a prefix - e.g. tyk.keys.*)
func (r *RedisCluster) GetKeys(filter string) []string {
	if err := r.up(); err != nil {
		log.Debug(err)
		return nil
	}

	singleton, err := r.singleton()
	if err != nil {
		log.Error(err)
		return nil
	}

	filterHash := ""
	if filter != "" {
		filterHash = r.hashKey(filter)
	}
	searchStr := r.KeyPrefix + filterHash + "*"
	log.Debug("[STORE] Getting list by: ", searchStr)

	fnFetchKeys := func(client *redis.Client) ([]string, error) {
		values := make([]string, 0)

		iter := client.Scan(r.RedisController.ctx, 0, searchStr, 0).Iterator()
		for iter.Next(r.RedisController.ctx) {
			values = append(values, iter.Val())
		}

		if err := iter.Err(); err != nil {
			return nil, err
		}

		return values, nil
	}

	sessions := make([]string, 0)

	switch v := singleton.(type) {
	case *redis.ClusterClient:
		ch := make(chan []string)

		go func() {
			err = v.ForEachMaster(r.RedisController.ctx, func(ctx context.Context, client *redis.Client) error {
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

	singleton, err := r.singleton()
	if err != nil {
		log.Error(err)
		return nil
	}
	values := make([]string, 0)

	switch v := singleton.(type) {
	case *redis.ClusterClient:
		{
			getCmds := make([]*redis.StringCmd, 0)
			pipe := v.Pipeline()
			for _, key := range keys {
				getCmds = append(getCmds, pipe.Get(r.RedisController.ctx, key))
			}
			_, err := pipe.Exec(r.RedisController.ctx)
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
			result, err := v.MGet(r.RedisController.ctx, keys...).Result()
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

	singleton, err := r.singleton()
	if err != nil {
		log.Error(err)
		return false
	}

	n, err := singleton.Del(r.RedisController.ctx, r.fixKey(keyName)).Result()
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

	singleton, err := r.singleton()
	if err != nil {
		log.Error(err)
		return false
	}

	n, err := singleton.FlushAll(r.RedisController.ctx).Result()
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

	singleton, err := r.singleton()
	if err != nil {
		log.Error(err)
		return false
	}

	n, err := singleton.Del(r.RedisController.ctx, keyName).Result()
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
	singleton, err := r.singleton()
	if err != nil {
		log.Error(err)
		return false
	}
	log.Debug("Deleting: ", pattern)

	fnScan := func(client *redis.Client) ([]string, error) {
		values := make([]string, 0)

		iter := client.Scan(r.RedisController.ctx, 0, pattern, 0).Iterator()
		for iter.Next(r.RedisController.ctx) {
			values = append(values, iter.Val())
		}

		if err := iter.Err(); err != nil {
			return nil, err
		}

		return values, nil
	}

	var keys []string

	switch v := singleton.(type) {
	case *redis.ClusterClient:
		ch := make(chan []string)
		go func() {
			err = v.ForEachMaster(r.RedisController.ctx, func(ctx context.Context, client *redis.Client) error {
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
			err := singleton.Del(r.RedisController.ctx, name).Err()
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
		singleton, err := r.singleton()
		if err != nil {
			log.Error(err)
			return false
		}

		switch v := singleton.(type) {
		case *redis.ClusterClient:
			pipe := v.Pipeline()
			for _, k := range keys {
				pipe.Del(r.RedisController.ctx, k)
			}

			if _, err := pipe.Exec(r.RedisController.ctx); err != nil {
				log.Error("Error trying to delete keys:", err)
			}
		case *redis.Client:
			_, err := v.Del(r.RedisController.ctx, keys...).Result()
			if err != nil {
				log.Error("Error trying to delete keys: ", err)
			}
		}
	} else {
		log.Debug("RedisCluster called DEL - Nothing to delete")
	}

	return true
}

// StartPubSubHandler will listen for a signal and run the callback for
// every subscription and message event.
func (r *RedisCluster) StartPubSubHandler(ctx context.Context, channel string, callback func(interface{})) error {
	if err := r.up(); err != nil {
		return err
	}

	singleton, err := r.singleton()
	if err != nil {
		return err
	}

	pubsub := singleton.Subscribe(ctx, channel)
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