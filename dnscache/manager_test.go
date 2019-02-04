package dnscache

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestWrapDialerDialContextFunc(t *testing.T) {
	tearDownTestStorageFetchItem := setupTestStorageFetchItem(&configTestStorageFetchItem{t, etcHostsMap, etcHostsErrorMap})
	defer tearDownTestStorageFetchItem()

	expectedHost := "orig-host.com"
	hostWithPort := expectedHost + ":8078"
	dialerContext, cancel := context.WithCancel(context.TODO())
	cancel()

	cases := []struct {
		name string

		address     string
		initStorage bool

		shouldCallFetchItem bool
		shouldCallDelete    bool
		expectedHostname    string
		expectedError       string
	}{
		{
			"Should parse address, call storage.FetchItem, call storage.Delete on DialContext error",
			hostWithPort, true,
			true, true, expectedHost, "operation was canceled",
		},
		{
			"Shouldn't call FetchItem when caching is disabled(storage == nil)",
			hostWithPort, false,
			false, false, "", "",
		},
		{
			"Shouldn't cache ipv4 address",
			"192.0.2.10:80", true,
			false, false, "", "operation was canceled",
		},
		{
			"Should faifast on address without port(accept only address with port)",
			expectedHost, true,
			false, false, "", "missing port in address",
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

			_, err := dnsManager.WrapDialer(&net.Dialer{
				Timeout:   1 * time.Second,
				KeepAlive: 0,
			})(dialerContext, "tcp", tc.address)

			if tc.expectedError != "" {
				if err != nil && !strings.Contains(err.Error(), tc.expectedError) {
					t.Fatalf("wanted error '%s', got '%s'", tc.expectedError, err.Error())
				}
			}

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
