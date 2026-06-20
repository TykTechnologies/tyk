package dnscache

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
)

// Verifies: STK-REQ-021, SYS-REQ-109, SW-REQ-038
// STK-REQ-021:nominal:nominal
// STK-REQ-021:idempotency:nominal
// SYS-REQ-109:nominal:nominal
// SYS-REQ-109:idempotency:nominal
// SW-REQ-038:nominal:nominal
// SW-REQ-038:idempotency:nominal
func TestDnsCacheManagerRequirementStorageLifecycle(t *testing.T) {
	manager := NewDnsCacheManager(config.PickFirstStrategy)
	require.False(t, manager.IsCacheEnabled())
	require.Nil(t, manager.CacheStorage())

	storage := &MockStorage{
		MockFetchItem: func(key string) ([]string, error) { return nil, nil },
		MockGet:       func(key string) (DnsCacheItem, bool) { return DnsCacheItem{}, false },
		MockSet:       func(key string, addrs []string) {},
		MockDelete:    func(key string) {},
		MockClear:     func() {},
	}

	manager.SetCacheStorage(storage)
	require.True(t, manager.IsCacheEnabled())
	require.Same(t, storage, manager.CacheStorage())

	manager.InitDNSCaching(time.Second, time.Second)
	require.Same(t, storage, manager.CacheStorage())

	manager.DisposeCache()
	require.False(t, manager.IsCacheEnabled())
	require.Nil(t, manager.CacheStorage())

	manager.InitDNSCaching(time.Second, -1)
	require.True(t, manager.IsCacheEnabled())
	manager.DisposeCache()
}

// Verifies: STK-REQ-021, SYS-REQ-109, SW-REQ-038
// STK-REQ-021:error_handling:negative
// SYS-REQ-109:error_handling:negative
// SW-REQ-038:error_handling:negative
func TestDnsCacheManagerRequirementRandomStrategyGuard(t *testing.T) {
	manager := NewDnsCacheManager(config.PickFirstStrategy)

	ip, err := manager.getRandomIp([]string{"127.0.0.1"})

	require.Empty(t, ip)
	require.Error(t, err)
	require.Contains(t, err.Error(), "getRandomIp can be called only")
}

// Verifies: STK-REQ-021, SYS-REQ-109, SW-REQ-038
// STK-REQ-021:error_handling:negative
// SYS-REQ-109:error_handling:negative
// SW-REQ-038:error_handling:negative
func TestDnsCacheManagerRequirementFetchErrorFallsBackToOriginalAddress(t *testing.T) {
	manager := NewDnsCacheManager(config.PickFirstStrategy)
	var deleted bool
	manager.SetCacheStorage(&MockStorage{
		MockFetchItem: func(key string) ([]string, error) {
			return nil, errors.New("lookup failed")
		},
		MockGet:    func(key string) (DnsCacheItem, bool) { return DnsCacheItem{}, false },
		MockSet:    func(key string, addrs []string) {},
		MockDelete: func(key string) { deleted = true },
		MockClear:  func() {},
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := manager.WrapDialer(&net.Dialer{})(ctx, "tcp", "cache.example:443")

	require.Error(t, err)
	require.False(t, deleted)
}
