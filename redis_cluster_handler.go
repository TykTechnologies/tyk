package main

import (
	"errors"
	"github.com/garyburd/redigo/redis"
	"github.com/lonelycode/redigocluster/rediscluster"
	"strconv"
	"strings"
	"time"
)

// ------------------- REDIS CLUSTER STORAGE MANAGER -------------------------------

var redisClusterSingleton *rediscluster.RedisCluster

// RedisClusterStorageManager is a storage manager that uses the redis database.
type RedisClusterStorageManager struct {
	db        *rediscluster.RedisCluster
	KeyPrefix string
	HashKeys  bool
}

func NewRedisClusterPool() *rediscluster.RedisCluster {
	if redisClusterSingleton != nil {
		log.Debug("Redis pool already INITIALISED")
		return redisClusterSingleton
	}

	log.Info("Creating new Redis connection pool")

	maxIdle := 100
	if config.Storage.MaxIdle > 0 {
		maxIdle = config.Storage.MaxIdle
	}

	maxActive := 500
	if config.Storage.MaxActive > 0 {
		maxActive = config.Storage.MaxActive
	}

	thisPoolConf := rediscluster.PoolConfig{
		MaxIdle:     maxIdle,
		MaxActive:   maxActive,
		IdleTimeout: 240 * time.Second,
		Database:    config.Storage.Database,
		Password:    config.Storage.Password,
	}

	seed_redii := []map[string]string{}

	if len(config.Storage.Hosts) > 0 {
		for h, p := range config.Storage.Hosts {
			seed_redii = append(seed_redii, map[string]string{h: p})
		}
	} else {
		seed_redii = append(seed_redii, map[string]string{config.Storage.Host: strconv.Itoa(config.Storage.Port)})
	}

	thisInstance := rediscluster.NewRedisCluster(seed_redii, thisPoolConf, true)

	redisClusterSingleton = &thisInstance

	return &thisInstance
}

// Connect will establish a connection to the r.db
func (r *RedisClusterStorageManager) Connect() bool {

	if r.db == nil {
		log.Debug("Connecting to redis cluster")
		r.db = NewRedisClusterPool()
	} else {
		log.Debug("Storage Engine already initialised...")
	}

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

// GetKey will retreive a key from the database
func (r *RedisClusterStorageManager) GetKey(keyName string) (string, error) {
	if r.db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.GetKey(keyName)
	}
	log.Debug("[STORE] Getting WAS: ", keyName)
	log.Debug("[STORE] Getting: ", r.fixKey(keyName))
	value, err := redis.String(r.db.Do("GET", r.fixKey(keyName)))
	if err != nil {
		log.Debug("Error trying to get value:", err)
		return "", KeyError{}
	}

	return value, nil
}

func (r *RedisClusterStorageManager) GetRawKey(keyName string) (string, error) {
	if r.db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.GetRawKey(keyName)
	}
	value, err := redis.String(r.db.Do("GET", keyName))
	if err != nil {
		log.Debug("Error trying to get value:", err)
		return "", KeyError{}
	}

	return value, nil
}

func (r *RedisClusterStorageManager) GetExp(keyName string) (int64, error) {
	log.Debug("Getting exp for key: ", r.fixKey(keyName))
	if r.db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.GetExp(keyName)
	}

	value, err := redis.Int64(r.db.Do("TTL", r.fixKey(keyName)))
	if err != nil {
		log.Error("Error trying to get TTL: ", err)
	} else {
		return value, nil
	}

	return 0, KeyError{}
}

// SetKey will create (or update) a key value in the store
func (r *RedisClusterStorageManager) SetKey(keyName string, sessionState string, timeout int64) error {
	log.Debug("[STORE] SET Raw key is: ", keyName)
	log.Debug("[STORE] Setting key: ", r.fixKey(keyName))

	if r.db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.SetKey(keyName, sessionState, timeout)
	} else {
		_, err := r.db.Do("SET", r.fixKey(keyName), sessionState)
		if timeout > 0 {
			_, expErr := r.db.Do("EXPIRE", r.fixKey(keyName), timeout)
			if expErr != nil {
				log.Error("Could not EXPIRE key: ", expErr)
				return expErr
			}
		}
		if err != nil {
			log.Error("Error trying to set value: ", err)
			return err
		}
	}

	return nil
}

func (r *RedisClusterStorageManager) SetRawKey(keyName string, sessionState string, timeout int64) error {

	if r.db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.SetRawKey(keyName, sessionState, timeout)
	} else {
		_, err := r.db.Do("SET", keyName, sessionState)
		if timeout > 0 {
			_, expErr := r.db.Do("EXPIRE", keyName, timeout)
			if expErr != nil {
				log.Error("Could not EXPIRE key: ", expErr)
				return expErr
			}
		}
		if err != nil {
			log.Error("Error trying to set value: ", err)
			return err
		}
	}

	return nil
}

// Decrement will decrement a key in redis
func (r *RedisClusterStorageManager) Decrement(keyName string) {

	keyName = r.fixKey(keyName)
	log.Debug("Decrementing key: ", keyName)
	if r.db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		r.Decrement(keyName)
	} else {
		err := r.db.Send("DECR", keyName)

		if err != nil {
			log.Error("Error trying to decrement value:", err)
		}
	}
}

// IncrementWithExpire will increment a key in redis
func (r *RedisClusterStorageManager) IncrememntWithExpire(keyName string, expire int64) int64 {

	log.Debug("Incrementing raw key: ", keyName)
	if r.db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		r.IncrememntWithExpire(keyName, expire)
	} else {
		// This function uses a raw key, so we shouldn't call fixKey
		fixedKey := keyName
		val, err := redis.Int64(r.db.Do("INCR", fixedKey))
		log.Debug("Incremented key: ", fixedKey, ", val is: ", val)
		if val == 1 {
			log.Debug("--> Setting Expire")
			r.db.Send("EXPIRE", fixedKey, expire)
		}
		if err != nil {
			log.Error("Error trying to increment value:", err)
		}
		return val
	}
	return 0
}

// GetKeys will return all keys according to the filter (filter is a prefix - e.g. tyk.keys.*)
func (r *RedisClusterStorageManager) GetKeys(filter string) []string {
	if r.db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.GetKeys(filter)
	}

	searchStr := r.KeyPrefix + r.hashKey(filter) + "*"
	sessionsInterface, err := r.db.Do("KEYS", searchStr)
	if err != nil {
		log.Error("Error trying to get all keys:")
		log.Error(err)

	} else {
		sessions, _ := redis.Strings(sessionsInterface, err)
		for i, v := range sessions {
			sessions[i] = r.cleanKey(v)
		}

		return sessions
	}

	return []string{}
}

// GetKeysAndValuesWithFilter will return all keys and their values with a filter
func (r *RedisClusterStorageManager) GetKeysAndValuesWithFilter(filter string) map[string]string {

	if r.db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.GetKeysAndValuesWithFilter(filter)
	}

	searchStr := r.KeyPrefix + r.hashKey(filter) + "*"
	log.Debug("[STORE] Getting list by: ", searchStr)
	sessionsInterface, err := r.db.Do("KEYS", searchStr)
	if err != nil {
		log.Error("Error trying to get filtered client keys:")
		log.Error(err)

	} else {
		keys, _ := redis.Strings(sessionsInterface, err)
		valueObj, err := r.db.Do("MGET", sessionsInterface.([]interface{})...)
		values, err := redis.Strings(valueObj, err)

		returnValues := make(map[string]string)
		for i, v := range keys {
			returnValues[r.cleanKey(v)] = values[i]
		}

		return returnValues
	}

	return map[string]string{}
}

// GetKeysAndValues will return all keys and their values - not to be used lightly
func (r *RedisClusterStorageManager) GetKeysAndValues() map[string]string {

	if r.db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.GetKeysAndValues()
	}

	searchStr := r.KeyPrefix + "*"
	sessionsInterface, err := r.db.Do("KEYS", searchStr)
	if err != nil {
		log.Error("Error trying to get all keys:")
		log.Error(err)

	} else {
		keys, _ := redis.Strings(sessionsInterface, err)
		valueObj, err := r.db.Do("MGET", sessionsInterface.([]interface{})...)
		values, err := redis.Strings(valueObj, err)

		returnValues := make(map[string]string)
		for i, v := range keys {
			returnValues[r.cleanKey(v)] = values[i]
		}

		return returnValues
	}

	return map[string]string{}
}

// DeleteKey will remove a key from the database
func (r *RedisClusterStorageManager) DeleteKey(keyName string) bool {

	if r.db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.DeleteKey(keyName)
	}

	log.Debug("DEL Key was: ", keyName)
	log.Debug("DEL Key became: ", r.fixKey(keyName))
	_, err := r.db.Do("DEL", r.fixKey(keyName))
	if err != nil {
		log.Error("Error trying to delete key:")
		log.Error(err)
	}

	return true
}

// DeleteKey will remove a key from the database without prefixing, assumes user knows what they are doing
func (r *RedisClusterStorageManager) DeleteRawKey(keyName string) bool {

	if r.db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.DeleteRawKey(keyName)
	}

	_, err := r.db.Do("DEL", keyName)
	if err != nil {
		log.Error("Error trying to delete key:")
		log.Error(err)
	}

	return true
}

// DeleteKeys will remove a group of keys in bulk
func (r *RedisClusterStorageManager) DeleteKeys(keys []string) bool {

	if r.db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.DeleteKeys(keys)
	}

	if len(keys) > 0 {
		asInterface := make([]interface{}, len(keys))
		for i, v := range keys {
			asInterface[i] = interface{}(r.fixKey(v))
		}

		log.Debug("Deleting: ", asInterface)
		_, err := r.db.Do("DEL", asInterface...)
		if err != nil {
			log.Error("Error trying to delete keys:")
			log.Error(err)
		}
	} else {
		log.Debug("RedisClusterStorageManager called DEL - Nothing to delete")
	}

	return true
}

// DeleteKeys will remove a group of keys in bulk without a prefix handler
func (r *RedisClusterStorageManager) DeleteRawKeys(keys []string, prefix string) bool {

	if r.db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.DeleteKeys(keys)
	}

	if len(keys) > 0 {
		asInterface := make([]interface{}, len(keys))
		for i, v := range keys {
			asInterface[i] = interface{}(prefix + v)
		}

		log.Debug("Deleting: ", asInterface)
		_, err := r.db.Do("DEL", asInterface...)
		if err != nil {
			log.Error("Error trying to delete keys:")
			log.Error(err)
		}
	} else {
		log.Debug("RedisClusterStorageManager called DEL - Nothing to delete")
	}

	return true
}

// StartPubSubHandler will listen for a signal and run the callback with the message
func (r *RedisClusterStorageManager) StartPubSubHandler(channel string, callback func(redis.Message)) error {
	psc := redis.PubSubConn{r.db.RandomRedisHandle().Pool.Get()}
	psc.Subscribe(channel)
	for {
		switch v := psc.Receive().(type) {
		case redis.Message:
			callback(v)

		case redis.Subscription:
			log.Debug("Subscription started: ", v.Channel)

		case error:
			log.Error("Redis disconnected or error received, attempting to reconnect: ", v)

			return v
		}
	}
	return errors.New("Connection closed.")
	return nil
}

func (r *RedisClusterStorageManager) Publish(channel string, message string) error {
	if r.db == nil {
		log.Info("Connection dropped, Connecting..")
		r.Connect()
		r.Publish(channel, message)
	} else {
		_, err := r.db.Do("PUBLISH", channel, message)
		if err != nil {
			log.Error("Error trying to set value:")
			log.Error(err)
			return err
		}
	}
	return nil
}

func (r *RedisClusterStorageManager) GetAndDeleteSet(keyName string) []interface{} {

	log.Debug("Getting raw gkey set: ", keyName)
	if r.db == nil {
		log.Warning("Connection dropped, connecting..")
		r.Connect()
		r.GetAndDeleteSet(keyName)
	} else {
		log.Debug("keyName is: ", keyName)
		fixedKey := r.fixKey(keyName)
		log.Debug("Fixed keyname is: ", fixedKey)
		r.db.Send("MULTI")
		// Get all the elements
		r.db.Send("LRANGE", fixedKey, 0, -1)
		// Trim it to zero
		r.db.Send("DEL", fixedKey)
		// Execute
		r, err := redis.Values(r.db.Do("EXEC"))

		if len(r) == 0 {
			return []interface{}{}
		}

		vals := r[0].([]interface{})

		log.Debug("Returned: ", vals)

		if err != nil {
			log.Error("Multi command failed: ", err)
		}

		return vals
	}
	return []interface{}{}
}

func (r *RedisClusterStorageManager) AppendToSet(keyName string, value string) {

	log.Debug("Pushing to raw key set: ", keyName)
	if r.db == nil {
		log.Warning("Connection dropped, connecting..")
		r.Connect()
		r.AppendToSet(keyName, value)
	} else {
		_, err := r.db.Do("RPUSH", r.fixKey(keyName), value)

		if err != nil {
			log.Debug("Error trying to delete keys:")
			log.Debug(err)
		}

		return
	}
}

// IncrementWithExpire will increment a key in redis
func (r *RedisClusterStorageManager) SetRollingWindow(keyName string, per int64, expire int64) int {

	log.Debug("Incrementing raw key: ", keyName)
	if r.db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		r.SetRollingWindow(keyName, per, expire)
	} else {
		log.Debug("keyName is: ", keyName)
		now := time.Now()
		log.Debug("Now is:", now)
		onePeriodAgo := now.Add(time.Duration(-1*per) * time.Second)
		log.Debug("Then is: ", onePeriodAgo)

		r.db.Send("MULTI")
		// Drop the last period so we get current bucket
		r.db.Send("ZREMRANGEBYSCORE", keyName, "-inf", onePeriodAgo.UnixNano())
		// Get the set
		r.db.Send("ZRANGE", keyName, 0, -1)
		// Add this request to the pile
		r.db.Send("ZADD", keyName, now.UnixNano(), strconv.Itoa(int(now.UnixNano())))
		// REset the TTL so the key lives as long as the requests pile in
		r.db.Send("EXPIRE", keyName, per)
		r, err := redis.Values(r.db.Do("EXEC"))

		intVal := len(r[1].([]interface{}))

		log.Debug("Returned: ", intVal)

		if err != nil {
			log.Error("Multi command failed: ", err)
		}

		return intVal
	}
	return 0
}
