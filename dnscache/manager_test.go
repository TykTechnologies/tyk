package dnscache

import (
	"context"
	"net"
	"testing"
	"time"
)

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
			"Should parse address, call storage.FetchItem, call storage.Delete on DialContext error",
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
		{
			"Should parse address without port",
			expectedHost, dialerContext, true,
			true, true, expectedHost,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var fetchItemCall, deleteCall struct {
				called bool
				key    string
			}

			storage := &MockStorage{func(key string) ([]string, error) {
				fetchItemCall.called = true
				fetchItemCall.key = key
				return etcHostsMap[key+"."], nil
			}, func(key string) (DnsCacheItem, bool) {
				if _, ok := etcHostsMap[key]; ok {
					return DnsCacheItem{}, true
				}

				return DnsCacheItem{}, false
			}, func(key string, addrs []string) {},
			func(key string) {
				deleteCall.called = true
				deleteCall.key = key
			}, func() {}}

			dnsManager := NewDnsCacheManager()
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
			if tc.shouldCallDelete {
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
