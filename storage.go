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
	SetKey(string, string)         // Second input string is expected to be a JSON object (SessionState)
	GetKeys() []string
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
func (r *InMemoryStorageManager) Connect() bool {
	return true
}

// GetKey retrieves the key from the in-memory map
func (s InMemoryStorageManager) GetKey(keyName string) (string, error) {
	value, ok := s.Sessions[keyName]
	if !ok {
		return "", KeyError{}
	} else {
		return value, nil
	}
}

// SetKey updates the in-memory key
func (s InMemoryStorageManager) SetKey(keyName string, sessionState string) {
	s.Sessions[keyName] = sessionState
}

func (s InMemoryStorageManager) GetKeys() []string {
	sessions := make([]string, 0, len(s.Sessions))
	for key, _ := range s.Sessions {
		sessions = append(sessions, key)
	}

	return sessions
}

func (s InMemoryStorageManager) GetKeysAndValues() map[string]string {
	return s.Sessions
}

// DeleteKey will remove a key from the storage engine
func (s InMemoryStorageManager) DeleteKey(keyName string) bool {
	delete(s.Sessions, keyName)
	return true
}

// WillBulk remove keys from sessions DB
func (s InMemoryStorageManager) DeleteKeys(keys []string) bool {

	for _, keyName := range keys {
		delete(s.Sessions, keyName)
	}

	return true
}

// ------------------- REDIS STORAGE MANAGER -------------------------------

// RedisStorageManager is a storage manager that uses the redis database.
type RedisStorageManager struct {
	pool *redis.Pool
	KeyPrefix string
}

func (r *RedisStorageManager) newPool(server, password string) *redis.Pool {
	return &redis.Pool{
		MaxIdle: 3,
		IdleTimeout: 240 * time.Second,
		Dial: func () (redis.Conn, error) {
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

func (r *RedisStorageManager) GetKey(keyName string) (string, error) {
	db := r.pool.Get()
	defer db.Close()
	if db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.GetKey(keyName)
	} else {
		value, err := redis.String(db.Do("GET", r.fixKey(keyName)))
		if err != nil {
			log.Error("Error trying to get value:")
			log.Error(err)
		} else {

			return value, nil

		}
	}

	return "", KeyError{}
}

func (r *RedisStorageManager) SetKey(keyName string, sessionState string) {
	db := r.pool.Get()
	defer db.Close()
	if db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		r.SetKey(keyName, sessionState)
	} else {
		_, err := db.Do("SET", r.fixKey(keyName), sessionState)
		if err != nil {
			log.Error("Error trying to set value:")
			log.Error(err)
		}
	}
}

func (r *RedisStorageManager) GetKeys() []string {
	db := r.pool.Get()
	defer db.Close()
	if db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.GetKeys()
	} else {
		searchStr := r.KeyPrefix + "*"
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
	}
	return []string{}
}

func (r *RedisStorageManager) GetKeysAndValues() map[string]string {
	db := r.pool.Get()
	defer db.Close()
	if db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.GetKeysAndValues()
	} else {
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
	}
	return map[string]string{}
}

func (r *RedisStorageManager) DeleteKey(keyName string) bool {
	db := r.pool.Get()
	defer db.Close()
	if db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.DeleteKey(keyName)
	} else {
		_, err := db.Do("DEL", r.fixKey(keyName))
		if err != nil {
			log.Error("Error trying to delete key:")
			log.Error(err)
		}
	}
	return true
}

func (r *RedisStorageManager) DeleteKeys(keys []string) bool {
	db := r.pool.Get()
	defer db.Close()
	if db == nil {
		log.Info("Connection dropped, connecting..")
		r.Connect()
		return r.DeleteKeys(keys)
	} else {
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
	}
	return true
}
