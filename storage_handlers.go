package main

import (
	"github.com/garyburd/redigo/redis"
	"strconv"
	"strings"
	"time"
)

// KeyError is a standard error for when a key is not found in the storage engine
type KeyError struct{}

func (e KeyError) Error() string {
	return "Key not found"
}

// StorageHandler is a standard interface to a storage backend,
// used by AuthorisationManager to read and write key values to the backend
type StorageHandler interface {
	GetKey(string) (string, error) // Returned string is expected to be a JSON object (SessionState)
	SetKey(string, string, int64)  // Second input string is expected to be a JSON object (SessionState)
	GetKeys(string) []string
	DeleteKey(string) bool
	Connect() bool
	GetKeysAndValues() map[string]string
	DeleteKeys([]string) bool
}

// InMemoryStorageManager implements the StorageHandler interface,
// it uses an in-memory map to store sessions, should only be used
// for testing purposes
type InMemoryStorageManager struct {
	Sessions map[string]string
}

// Connect will establish a connection to the storage engine
func (s *InMemoryStorageManager) Connect() bool {
	return true
}

// GetKey retrieves the key from the in-memory map
func (s InMemoryStorageManager) GetKey(keyName string) (string, error) {
	value, ok := s.Sessions[keyName]
	if !ok {
		return "", KeyError{}
	}

	return value, nil

}

// SetKey updates the in-memory key
func (s InMemoryStorageManager) SetKey(keyName string, sessionState string, timeout int64) {
	s.Sessions[keyName] = sessionState
}

// GetKeys will retreive multiple keys based on a filter (prefix, e.g. tyk.keys)
func (s InMemoryStorageManager) GetKeys(filter string) []string {
	sessions := make([]string, 0, len(s.Sessions))
	for key := range s.Sessions {
		if strings.Contains(key, filter) {
			sessions = append(sessions, key)
		}
	}

	return sessions
}

// GetKeysAndValues returns all keys and their data, very expensive call.
func (s InMemoryStorageManager) GetKeysAndValues() map[string]string {
	return s.Sessions
}

// DeleteKey will remove a key from the storage engine
func (s InMemoryStorageManager) DeleteKey(keyName string) bool {
	delete(s.Sessions, keyName)
	return true
}

// DeleteKeys remove keys from sessions DB
func (s InMemoryStorageManager) DeleteKeys(keys []string) bool {

	for _, keyName := range keys {
		delete(s.Sessions, keyName)
	}

	return true
}

// ------------------- REDIS STORAGE MANAGER -------------------------------

// RedisStorageManager is a storage manager that uses the redis database.
type RedisStorageManager struct {
	pool      *redis.Pool
	KeyPrefix string
}

func (r *RedisStorageManager) newPool(server, password string) *redis.Pool {
	return &redis.Pool{
		MaxIdle:     3,
		IdleTimeout: 240 * time.Second,
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", server)
			if err != nil {
				return nil, err
			}
			if _, err := c.Do("AUTH", password); err != nil {
				c.Close()
				return nil, err
			}
			return c, err
		},
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			_, err := c.Do("PING")
			return err
		},
	}
}

// Connect will establish a connection to the DB
func (r *RedisStorageManager) Connect() bool {

	fullPath := config.Storage.Host + ":" + strconv.Itoa(config.Storage.Port)
	log.Info("Connecting to redis on: ", fullPath)
	r.pool = r.newPool(fullPath, config.Storage.Password)

	return true
}

func (r *RedisStorageManager) fixKey(keyName string) string {
	setKeyName := r.KeyPrefix + keyName
	return setKeyName
}

func (r *RedisStorageManager) cleanKey(keyName string) string {
	setKeyName := strings.Replace(keyName, r.KeyPrefix, "", 1)
	return setKeyName
}

// GetKey will retreive a key from the database
func (r *RedisStorageManager) GetKey(keyName string) (string, error) {
	db := r.pool.Get()
	defer db.Close()
	if db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.GetKey(keyName)
	}

	value, err := redis.String(db.Do("GET", r.fixKey(keyName)))
	if err != nil {
		log.Error("Error trying to get value:")
		log.Error(err)
	} else {
		return value, nil
	}


	return "", KeyError{}
}

// SetKey will create (or update) a key value in the store
func (r *RedisStorageManager) SetKey(keyName string, sessionState string, timeout int64) {
	db := r.pool.Get()
	defer db.Close()
	if db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		r.SetKey(keyName, sessionState, timeout)
	} else {
		_, err := db.Do("SET", r.fixKey(keyName), sessionState)
		if timeout > 0 {
			_, expErr := db.Do("EXPIRE", r.fixKey(keyName), timeout)
			if expErr != nil {
				log.Error("Could not EXPIRE key")
				log.Error(expErr)
			}
		}
		if err != nil {
			log.Error("Error trying to set value:")
			log.Error(err)
		}
	}
}

// GetKeys will return all keys according to the filter (filter is a prefix - e.g. tyk.keys.*)
func (r *RedisStorageManager) GetKeys(filter string) []string {
	db := r.pool.Get()
	defer db.Close()
	if db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.GetKeys(filter)
	}

	searchStr := r.KeyPrefix + filter + "*"
	sessionsInterface, err := db.Do("KEYS", searchStr)
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

// GetKeysAndValues will return all keys and their values - not to be used lightly
func (r *RedisStorageManager) GetKeysAndValues() map[string]string {
	db := r.pool.Get()
	defer db.Close()
	if db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.GetKeysAndValues()
	}

	searchStr := r.KeyPrefix + "*"
	sessionsInterface, err := db.Do("KEYS", searchStr)
	if err != nil {
		log.Error("Error trying to get all keys:")
		log.Error(err)

	} else {
		keys, _ := redis.Strings(sessionsInterface, err)
		valueObj, err := db.Do("MGET", sessionsInterface.([]interface{})...)
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
func (r *RedisStorageManager) DeleteKey(keyName string) bool {
	db := r.pool.Get()
	defer db.Close()
	if db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.DeleteKey(keyName)
	}

	_, err := db.Do("DEL", r.fixKey(keyName))
	if err != nil {
		log.Error("Error trying to delete key:")
		log.Error(err)
	}

	return true
}

// DeleteKeys will remove a group of keys in bulk
func (r *RedisStorageManager) DeleteKeys(keys []string) bool {
	db := r.pool.Get()
	defer db.Close()
	if db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.DeleteKeys(keys)
	}

	if len(keys) > 0 {
		asInterface := make([]interface{}, len(keys))
		for i, v := range keys {
			asInterface[i] = interface{}(r.fixKey(v))
		}
		_, err := db.Do("DEL", asInterface...)
		if err != nil {
			log.Error("Error trying to delete keys:")
			log.Error(err)
		}
	} else {
		log.Info("RedisStorageManager called DEL - Nothing to delete")
	}

	return true
}
