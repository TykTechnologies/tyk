package certcheck

//go:generate mockgen -destination=./cache_mock.go -package certcheck . CooldownCache

import (
	"errors"
	"fmt"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/TykTechnologies/tyk/storage"
)

const (
	// Certificate check cooldown key prefix for Redis
	certCheckCooldownPrefix = "cert_check_cooldown:"
	// Certificate expiry event cooldown key prefix for Redis
	certExpiryEventCooldownPrefix = "cert_expiry_event_cooldown:"
)

var (

	// ErrCheckCooldownDoesNotExist indicates that no check cooldown exists for the specified identifier in the cache.
	ErrCheckCooldownDoesNotExist = errors.New("check cooldown does not exist")
	// ErrFireEventCooldownDoesNotExist indicates that no fire event cooldown exists for the specified identifier in the cache.
	ErrFireEventCooldownDoesNotExist = errors.New("fire event cooldown does not exist")
)

// Cooldowns is a struct that holds the cooldowns for a certificate.
type Cooldowns struct {
	CheckCooldown     time.Time
	FireEventCooldown time.Time
}

// CooldownCache is an interface for a cache that stores cooldowns for certificates.
type CooldownCache interface {
	HasCheckCooldown(certID string) (exists bool, err error)
	IsCheckCooldownActive(certID string) (active bool, err error)
	SetCheckCooldown(certID string, checkCooldownInSeconds int64) error
	HasFireEventCooldown(certID string) (exists bool, err error)
	IsFireEventCooldownActive(certID string) (active bool, err error)
	SetFireEventCooldown(certID string, fireEventCooldownInSeconds int64) error
}

var cooldownLRUCache *lru.Cache[string, Cooldowns]
var cooldownLRUCacheMutex = &sync.RWMutex{}

// GetCooldownLRUCache returns the LRU cache for cooldowns. It is initialized if it does not exist yet.
// Using the singleton pattern here to ensure that the cache is always initialized.
func GetCooldownLRUCache() *lru.Cache[string, Cooldowns] {
	if cooldownLRUCache == nil {
		var err error
		cooldownLRUCache, err = lru.New[string, Cooldowns](512)
		if err != nil {
			// This should actually never happen. But it helps us to ensure that the cache is always initialized.
			panic(err)
		}
	}
	return cooldownLRUCache
}

// InMemoryCooldownCache is a cache that stores cooldowns for certificates in memory.
type InMemoryCooldownCache struct {
}

// NewInMemoryCooldownCache creates a new InMemoryCooldownCache.
func NewInMemoryCooldownCache() (*InMemoryCooldownCache, error) {
	return &InMemoryCooldownCache{}, nil
}

// HasCheckCooldown checks if a check cooldown exists for the specified identifier.
func (mem *InMemoryCooldownCache) HasCheckCooldown(certID string) (exists bool, err error) {
	cooldownLRUCacheMutex.RLock()
	defer cooldownLRUCacheMutex.RUnlock()
	return GetCooldownLRUCache().Contains(certID), nil
}

// IsCheckCooldownActive checks if a check cooldown is active for the specified identifier.
func (mem *InMemoryCooldownCache) IsCheckCooldownActive(certID string) (active bool, err error) {
	cooldownLRUCacheMutex.RLock()
	defer cooldownLRUCacheMutex.RUnlock()

	now := time.Now()
	cooldowns, ok := GetCooldownLRUCache().Get(certID)
	if !ok {
		return false, ErrCheckCooldownDoesNotExist
	}

	if now.Before(cooldowns.CheckCooldown) {
		return true, nil
	}

	return false, nil
}

// SetCheckCooldown sets a check cooldown for the specified identifier.
func (mem *InMemoryCooldownCache) SetCheckCooldown(certID string, checkCooldownInSeconds int64) error {
	cooldownLRUCacheMutex.Lock()
	defer cooldownLRUCacheMutex.Unlock()

	now := time.Now()
	cooldownEndTime := now.Add(time.Duration(checkCooldownInSeconds) * time.Second)

	cooldowns, ok := GetCooldownLRUCache().Get(certID)
	if ok {
		cooldowns.CheckCooldown = cooldownEndTime
		GetCooldownLRUCache().Add(certID, cooldowns)
		return nil
	}

	newCooldowns := Cooldowns{
		CheckCooldown:     cooldownEndTime,
		FireEventCooldown: now,
	}
	GetCooldownLRUCache().Add(certID, newCooldowns)
	return nil
}

// HasFireEventCooldown checks if a fire event cooldown exists for the specified identifier.
func (mem *InMemoryCooldownCache) HasFireEventCooldown(certID string) (exists bool, err error) {
	cooldownLRUCacheMutex.RLock()
	defer cooldownLRUCacheMutex.RUnlock()
	return GetCooldownLRUCache().Contains(certID), nil
}

// IsFireEventCooldownActive checks if a fire event cooldown is active for the specified identifier.
func (mem *InMemoryCooldownCache) IsFireEventCooldownActive(certID string) (active bool, err error) {
	cooldownLRUCacheMutex.RLock()
	defer cooldownLRUCacheMutex.RUnlock()

	now := time.Now()
	cooldowns, ok := GetCooldownLRUCache().Get(certID)
	if !ok {
		return false, ErrFireEventCooldownDoesNotExist
	}

	if now.Before(cooldowns.FireEventCooldown) {
		return true, nil
	}

	return false, nil
}

// SetFireEventCooldown sets a fire event cooldown for the specified identifier.
func (mem *InMemoryCooldownCache) SetFireEventCooldown(certID string, fireEventCooldownInSeconds int64) error {
	cooldownLRUCacheMutex.Lock()
	defer cooldownLRUCacheMutex.Unlock()

	now := time.Now()
	cooldownEndTime := now.Add(time.Duration(fireEventCooldownInSeconds) * time.Second)

	newCooldowns := Cooldowns{
		CheckCooldown:     now,
		FireEventCooldown: cooldownEndTime,
	}
	GetCooldownLRUCache().Add(certID, newCooldowns)
	return nil
}

// RedisCooldownCache is a cache that stores cooldowns for certificates in Redis.
type RedisCooldownCache struct {
	redisStorage storage.Handler
}

// NewRedisCooldownCache creates a new RedisCooldownCache.
func NewRedisCooldownCache(redisStorage storage.Handler) (*RedisCooldownCache, error) {
	return &RedisCooldownCache{
		redisStorage: redisStorage,
	}, nil
}

// HasCheckCooldown checks if a check cooldown exists for the specified identifier.
func (r *RedisCooldownCache) HasCheckCooldown(certID string) (exists bool, err error) {
	return r.redisStorage.Exists(r.checkKey(certID))
}

// IsCheckCooldownActive checks if a check cooldown is active for the specified identifier.
func (r *RedisCooldownCache) IsCheckCooldownActive(certID string) (active bool, err error) {
	_, err = r.redisStorage.GetKey(r.checkKey(certID))
	if errors.Is(err, storage.ErrKeyNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

// SetCheckCooldown sets a check cooldown for the specified identifier.
func (r *RedisCooldownCache) SetCheckCooldown(certID string, checkCooldownInSeconds int64) error {
	return r.redisStorage.SetKey(r.checkKey(certID), "1", checkCooldownInSeconds)
}

// HasFireEventCooldown checks if a fire event cooldown exists for the specified identifier.
func (r *RedisCooldownCache) HasFireEventCooldown(certID string) (exists bool, err error) {
	return r.redisStorage.Exists(r.fireEventKey(certID))
}

// IsFireEventCooldownActive checks if a fire event cooldown is active for the specified identifier.
func (r *RedisCooldownCache) IsFireEventCooldownActive(certID string) (active bool, err error) {
	_, err = r.redisStorage.GetKey(r.fireEventKey(certID))
	if errors.Is(err, storage.ErrKeyNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

// SetFireEventCooldown sets a fire event cooldown for the specified identifier.
func (r *RedisCooldownCache) SetFireEventCooldown(certID string, fireEventCooldownInSeconds int64) error {
	return r.redisStorage.SetKey(r.fireEventKey(certID), "1", fireEventCooldownInSeconds)
}

func (r *RedisCooldownCache) checkKey(certID string) string {
	return fmt.Sprintf("%s%s", certCheckCooldownPrefix, certID)
}

func (r *RedisCooldownCache) fireEventKey(certID string) string {
	return fmt.Sprintf("%s%s", certExpiryEventCooldownPrefix, certID)
}

// Interface Guards
var _ CooldownCache = (*InMemoryCooldownCache)(nil)
var _ CooldownCache = (*RedisCooldownCache)(nil)
