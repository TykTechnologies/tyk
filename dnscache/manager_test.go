package dnscache_test

import (
	"context"
	"github.com/TykTechnologies/tyk/dnscache"
	"net"
	"testing"
	"time"
)

type mockStorage struct {
	mockFetchItem func(key string) ([]string, error)
	mockGet       func(key string) (dnscache.DnsCacheItem, bool)
	mockDelete    func(key string)
	mockClear     func()
}

func (ms *mockStorage) FetchItem(key string) ([]string, error) {
	return ms.mockFetchItem(key)
}

func (ms *mockStorage) Get(key string) (dnscache.DnsCacheItem, bool) {
	return ms.mockGet(key)
}

func (ms *mockStorage) Delete(key string) {
	ms.mockDelete(key)
}

func (ms *mockStorage) Clear() {
	ms.mockClear()
}

func TestWrapDialerDialContextFunc(t *testing.T) {
	tearDownTestStorageFetchItem := setupTestStorageFetchItem(&configTestStorageFetchItem{t, etcHostsMap, etcHostsErrorMap,})
	defer tearDownTestStorageFetchItem()

	expectedHost := "orig-host.com"
	hostWithPort := expectedHost + ":8080"
	dialerContext, _ := context.WithTimeout(context.TODO(), 1 * time.Second)

	cases := []struct {
		name string

		address       string
		dialerContext context.Context
		initStorage bool

		shouldCallFetchItem bool
		shouldCallDelete bool
		expectedHostname    string
	}{
		{
			"Should parse address and call storage.FetchItem",
			hostWithPort, dialerContext, true,
			true, true, expectedHost,
		},
		{
			"Shouldn't call FetchItem when caching is disabled(storage == nil)",
			hostWithPort, dialerContext, false,
			false, false, "",
		},
		{
			"Shouldn't cache ipv4 address",
			"192.0.2.10:80", dialerContext, true,
			false, false, "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var fetchItemCall, deleteCall struct {
				called bool
				key    string
			}

			storage := &mockStorage{func(key string) ([]string, error) {
				fetchItemCall.called = true
				fetchItemCall.key = key
				return etcHostsMap[key+"."], nil
			}, func(key string) (dnscache.DnsCacheItem, bool) {
				if _, ok := etcHostsMap[key]; ok {
					return dnscache.DnsCacheItem{}, true
				}

				return dnscache.DnsCacheItem{}, false
			}, func(key string) {
				deleteCall.called = true
				deleteCall.key = key
			}, func() {}}

			dnsManager := dnscache.NewDnsCacheManager()
			if tc.initStorage {
				dnsManager.SetCacheStorage(storage)
			}

			dnsManager.WrapDialer(&net.Dialer{
				Timeout: 1 * time.Second,
			})(tc.dialerContext, "tcp", tc.address)

			if tc.shouldCallFetchItem != fetchItemCall.called {
				t.Fatalf("wanted fetchItemCall.called to be %v, got %v", tc.shouldCallFetchItem, fetchItemCall.called)
			}

			if tc.shouldCallFetchItem {
				if fetchItemCall.key != tc.expectedHostname {
					t.Fatalf("wanted fetchItemCall.key to be %v, got %v", tc.expectedHostname, fetchItemCall.key)
				}
			}

			if tc.shouldCallDelete != deleteCall.called {
				t.Fatalf("wanted deleteCall.called to be %v, got %v", tc.shouldCallDelete, deleteCall.called)
			}
			if tc.shouldCallFetchItem {
				if deleteCall.key != tc.expectedHostname {
					t.Fatalf("wanted deleteCall.key to be %v, got %v", tc.expectedHostname, deleteCall.key)
				}
			}

			if tc.initStorage {
				dnsManager.DisposeCache()
			}
		})
	}
}
