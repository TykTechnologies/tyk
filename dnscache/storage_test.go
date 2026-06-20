package dnscache

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/TykTechnologies/tyk/test"
)

var (
	expiration    = 10
	checkInterval = 5
)

const (
	host             = "orig-host.com."
	singleRecordHost = "single.orig-host.com."
	host2            = "orig-host2.com."
	host3            = "some.orig-host3.com"
	host4            = "some.orig-host4.com"
	hostErrorable    = "unknown.orig-host.com."
	wsHost           = "ws.orig-host.com."
)

var (
	etcHostsMap = map[string][]string{
		singleRecordHost: {"10.0.2.10"},
		host:             {"127.0.0.1", "127.0.0.2", "127.0.0.3"},
		host2:            {"10.0.2.0", "10.0.2.1", "10.0.2.2"},
		host3:            {"10.0.2.15", "10.0.2.16"},
		host4:            {"10.0.2.11", "10.0.2.10"},
		wsHost:           {"127.0.0.1", "127.0.0.1"},
	}

	etcHostsErrorMap = map[string]int{
		hostErrorable: dns.RcodeServerFailure,
	}
)

type configTestStorageFetchItem struct {
	*testing.T
	etcHostsMap       map[string][]string
	etcHostsErrorsMap map[string]int
}

func setupTestStorageFetchItem(cfg *configTestStorageFetchItem) func() {
	handle, err := test.InitDNSMock(cfg.etcHostsMap, cfg.etcHostsErrorsMap)
	if err != nil {
		cfg.T.Error(err.Error())
	}

	return func() {
		if err := handle.ShutdownDnsMock(); err != nil {
			cfg.T.Error(err.Error())
		}
	}
}

// Verifies: STK-REQ-021, SYS-REQ-109, SW-REQ-035
// SW-REQ-035:nominal:nominal
// SW-REQ-035:error_handling:nominal
func TestStorageFetchItem(t *testing.T) {
	dnsCache := NewDnsCacheStorage(time.Duration(expiration)*time.Second, time.Duration(checkInterval)*time.Second)

	tearDownTestStorageFetchItem := setupTestStorageFetchItem(&configTestStorageFetchItem{t, etcHostsMap, etcHostsErrorMap})
	defer func() {
		tearDownTestStorageFetchItem()
		dnsCache.Clear()
		dnsCache = nil
	}()

	cases := []struct {
		name string

		Host        string
		ExpectedIPs []string

		expectedErrorType    reflect.Type
		shouldExistInCache   bool
		shouldBeAddedToCache bool
	}{
		{
			"Should cache first dns record first fetch",
			host, etcHostsMap[host],
			nil, false, true,
		},
		{
			"Should cache second dns record first fetch",
			host2, etcHostsMap[host2],
			nil, false, true,
		},
		{
			"Should populate from cache first dns record second fetch",
			host, etcHostsMap[host],
			nil, true, false,
		},
		{
			"Should populate from cache first dns record third fetch",
			host, etcHostsMap[host],
			nil, true, false,
		},
		{
			"Should populate from cache second dns record second fetch",
			host2, etcHostsMap[host2],
			nil, true, false,
		},
		{
			"Shouldn't cache dns record fetch in case error",
			hostErrorable, nil,
			reflect.TypeOf(&net.DNSError{}), false, false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := dnsCache.FetchItem(tc.Host)

			if tc.expectedErrorType != nil {
				if err == nil || tc.expectedErrorType != reflect.TypeOf(err) {
					t.Fatalf("wanted FetchItem error type %v, got %v. Error=%#v", tc.expectedErrorType, reflect.TypeOf(err), err)
				}

				if _, ok := dnsCache.Get(tc.Host); got != nil || ok {
					t.Fatalf("wanted FetchItem error to omit cache. got %#v, ok=%t", got, ok)
				}
				return
			}

			if err != nil || !reflect.DeepEqual(got, tc.ExpectedIPs) {
				t.Fatalf("wanted ips %q, got %q. Error: %v", tc.ExpectedIPs, got, err)
			}

			if tc.shouldExistInCache || tc.shouldBeAddedToCache {
				record, ok := dnsCache.Get(tc.Host)

				if !ok {
					t.Fatalf("Host addresses weren't found in cache; host %q", tc.Host)
				}

				if !test.IsDnsRecordsAddrsEqualsTo(record.Addrs, tc.ExpectedIPs) {
					t.Fatalf("wanted cached ips %v, got record %v", tc.ExpectedIPs, record)
				}
			} else {
				if got, ok := dnsCache.Get(tc.Host); !test.IsDnsRecordsAddrsEqualsTo(got.Addrs, nil) || ok {
					t.Fatalf("wanted FetchItem to omit write to cache. got %#v, ok=%t", got, ok)
				}
			}
		})
	}
}

// Verifies: STK-REQ-021, SYS-REQ-109, SW-REQ-035
// SW-REQ-035:boundary:nominal
func TestStorageRecordExpiration(t *testing.T) {
	cases := []struct {
		name         string
		expiration   time.Duration
		wait         time.Duration
		wantItemLive bool
	}{
		{
			name:         "zero expiration keeps record live",
			expiration:   0,
			wait:         20 * time.Millisecond,
			wantItemLive: true,
		},
		{
			name:         "positive expiration keeps record live before deadline",
			expiration:   time.Second,
			wait:         20 * time.Millisecond,
			wantItemLive: true,
		},
		{
			name:         "positive expiration hides expired record without janitor cleanup",
			expiration:   20 * time.Millisecond,
			wait:         60 * time.Millisecond,
			wantItemLive: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dnsCache := NewDnsCacheStorage(tc.expiration, -1)
			t.Cleanup(dnsCache.Clear)

			dnsCache.Set(host, etcHostsMap[host])
			time.Sleep(tc.wait)

			item, ok := dnsCache.Get(host)
			if ok != tc.wantItemLive {
				t.Fatalf("wanted live item=%t, got ok=%t item=%#v", tc.wantItemLive, ok, item)
			}

			items := dnsCache.Items(false)
			_, itemListed := items[host]
			if itemListed != tc.wantItemLive {
				t.Fatalf("wanted listed item=%t, got items=%+v", tc.wantItemLive, items)
			}
		})
	}
}
