package main

import (
	"github.com/garyburd/redigo/redis"
	"strconv"
	"strings"
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

// DeleteKey will remove a key from the storage engine
func (s InMemoryStorageManager) DeleteKey(keyName string) bool {
	delete(s.Sessions, keyName)
	return true
}

// ------------------- REDIS STORAGE MANAGER -------------------------------

// RedisStorageManager is a storage manager that uses the redis database.
type RedisStorageManager struct {
	db        redis.Conn
	KeyPrefix string
}

func (r *RedisStorageManager) Connect() bool {
	var err error
	fullPath := config.Storage.Host + ":" + strconv.Itoa(config.Storage.Port)
	log.Info("Connecting to redis on: ", fullPath)
	r.db, err = redis.Dial("tcp", fullPath)
	if err != nil {
		log.Error("Couldn't connect to host")
		log.Error(err)
	}

	if _, err := r.db.Do("AUTH", config.Storage.Password); err != nil {
		r.db.Close()
		log.Error("Couldn't log into redis server:")
		log.Error(err)
		return false
	}

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

func (r RedisStorageManager) GetKey(keyName string) (string, error) {
	if r.db == nil {
		r.Connect()
		return r.GetKey(keyName)
	} else {
		value, err := redis.String(r.db.Do("GET", r.fixKey(keyName)))
		if err != nil {
			log.Error("Error trying to get value:")
			log.Error(err)
		} else {

			return value, nil

		}
	}

	return "", KeyError{}
}

func (r RedisStorageManager) SetKey(keyName string, sessionState string) {
	if r.db == nil {
		r.Connect()
		r.SetKey(keyName, sessionState)
	} else {
		_, err := r.db.Do("SET", r.fixKey(keyName), sessionState)
		if err != nil {
			log.Error("Error trying to set value:")
			log.Error(err)
		}
	}
}

func (r RedisStorageManager) GetKeys() []string {
	if r.db == nil {
		r.Connect()
		return r.GetKeys()
	} else {
		searchStr := r.KeyPrefix + "*"
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
	}
	return []string{}
}

func (r RedisStorageManager) DeleteKey(keyName string) bool {
	if r.db == nil {
		r.Connect()
		return r.DeleteKey(keyName)
	} else {
		_, err := r.db.Do("DEL", r.fixKey(keyName))
		if err != nil {
			log.Error("Error trying to delete key:")
			log.Error(err)
		}
	}
	return true
}
