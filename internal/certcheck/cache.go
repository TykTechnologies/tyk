package certcheck

//go:generate mockgen -destination=./cache_mock.go -package certcheck . CooldownCache

import (
	"errors"
	"fmt"
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
	ErrCheckCooldownDoesNotExist     = errors.New("check cooldown does not exist")
	ErrFireEventCooldownDoesNotExist = errors.New("fire event cooldown does not exist")
)

type Cooldowns struct {
	CheckCooldown     time.Time
	FireEventCooldown time.Time
}

type CooldownCache interface {
	HasCheckCooldown(certID string) (exists bool, err error)
	IsCheckCooldownActive(certID string) (active bool, err error)
	SetCheckCooldown(certID string, checkCooldownInSeconds int64) error
	HasFireEventCooldown(certID string) (exists bool, err error)
	IsFireEventCooldownActive(certID string) (active bool, err error)
	SetFireEventCooldown(certID string, fireEventCooldownInSeconds int64) error
}

type LocalCooldownCache struct {
	lruCache *lru.Cache[string, Cooldowns]
}

func NewLocalCooldownCache(size int) (*LocalCooldownCache, error) {
	lruCache, err := lru.New[string, Cooldowns](size)
	if err != nil {
		return nil, err
	}

	return &LocalCooldownCache{
		lruCache: lruCache,
	}, nil
}

func (l *LocalCooldownCache) HasCheckCooldown(certID string) (exists bool, err error) {
	return l.lruCache.Contains(certID), nil
}

func (l *LocalCooldownCache) IsCheckCooldownActive(certID string) (active bool, err error) {
	now := time.Now()
	cooldowns, ok := l.lruCache.Get(certID)
	if !ok {
		return false, ErrCheckCooldownDoesNotExist
	}

	if now.Before(cooldowns.CheckCooldown) {
		return true, nil
	}

	return false, nil
}

func (l *LocalCooldownCache) SetCheckCooldown(certID string, checkCooldownInSeconds int64) error {
	now := time.Now()
	cooldownEndTime := now.Add(time.Duration(checkCooldownInSeconds) * time.Second)

	cooldowns, ok := l.lruCache.Get(certID)
	if ok {
		cooldowns.CheckCooldown = cooldownEndTime
		l.lruCache.Add(certID, cooldowns)
	}

	newCooldowns := Cooldowns{
		CheckCooldown:     cooldownEndTime,
		FireEventCooldown: now,
	}
	l.lruCache.Add(certID, newCooldowns)
	return nil
}

func (l *LocalCooldownCache) HasFireEventCooldown(certID string) (exists bool, err error) {
	return l.lruCache.Contains(certID), nil
}

func (l *LocalCooldownCache) IsFireEventCooldownActive(certID string) (active bool, err error) {
	now := time.Now()
	cooldowns, ok := l.lruCache.Get(certID)
	if !ok {
		return false, ErrFireEventCooldownDoesNotExist
	}

	if now.Before(cooldowns.FireEventCooldown) {
		return true, nil
	}

	return false, nil
}

func (l *LocalCooldownCache) SetFireEventCooldown(certID string, fireEventCooldownInSeconds int64) error {
	now := time.Now()
	cooldownEndTime := now.Add(time.Duration(fireEventCooldownInSeconds) * time.Second)

	cooldowns, ok := l.lruCache.Get(certID)
	if ok {
		cooldowns.FireEventCooldown = cooldownEndTime
		l.lruCache.Add(certID, cooldowns)
	}

	newCooldowns := Cooldowns{
		CheckCooldown:     now,
		FireEventCooldown: cooldownEndTime,
	}
	l.lruCache.Add(certID, newCooldowns)
	return nil
}

type RedisCooldownCache struct {
	redisStorage storage.Handler
}

func NewRedisCooldownCache(redisStorage storage.Handler) (*RedisCooldownCache, error) {
	return &RedisCooldownCache{
		redisStorage: redisStorage,
	}, nil
}

func (r *RedisCooldownCache) HasCheckCooldown(certID string) (exists bool, err error) {
	return r.redisStorage.Exists(r.checkKey(certID))
}

func (r *RedisCooldownCache) IsCheckCooldownActive(certID string) (active bool, err error) {
	_, err = r.redisStorage.GetKey(r.checkKey(certID))
	if errors.Is(err, storage.ErrKeyNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func (r *RedisCooldownCache) SetCheckCooldown(certID string, checkCooldownInSeconds int64) error {
	return r.redisStorage.SetKey(r.checkKey(certID), "1", checkCooldownInSeconds)
}

func (r *RedisCooldownCache) HasFireEventCooldown(certID string) (exists bool, err error) {
	return r.redisStorage.Exists(r.fireEventKey(certID))
}

func (r *RedisCooldownCache) IsFireEventCooldownActive(certID string) (active bool, err error) {
	_, err = r.redisStorage.GetKey(r.fireEventKey(certID))
	if errors.Is(err, storage.ErrKeyNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

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
var _ CooldownCache = (*LocalCooldownCache)(nil)
var _ CooldownCache = (*RedisCooldownCache)(nil)
