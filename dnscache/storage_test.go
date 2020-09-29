package dnscache

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/TykTechnologies/tyk/v3/test"
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

func TestStorageRecordExpiration(t *testing.T) {
	var (
		expiration    = 2000
		checkInterval = 1500
	)

	type testRecord struct {
		dns      string
		addrs    []string
		addDelay time.Duration
	}

	cases := []struct {
		name string

		records              []testRecord
		sleepBeforeCleanup   time.Duration
		notExpiredAfterDelay []testRecord
		checkInterval        int
	}{
		{
			"Shouldn't remove dns record when ttl/expiration < 1",
			[]testRecord{
				{dns: host, addrs: etcHostsMap[host]},
			},
			time.Duration(checkInterval+10) * time.Millisecond,
			[]testRecord{
				{dns: host, addrs: etcHostsMap[host]},
			},
			checkInterval,
		},
		{
			"Should remove single dns record after expiration",
			[]testRecord{
				{dns: host, addrs: etcHostsMap[host]},
			},
			time.Duration(expiration+10) * time.Millisecond,
			[]testRecord{},
			checkInterval,
		},
		{
			"Should leave as expired dns records if check_interval=-1",
			[]testRecord{
				{dns: host, addrs: etcHostsMap[host]},
				{dns: host2, addrs: etcHostsMap[host2]},
				{dns: wsHost, addrs: etcHostsMap[wsHost]},
			},
			time.Duration(checkInterval+10) * time.Millisecond,
			[]testRecord{
				{dns: host, addrs: etcHostsMap[host]},
				{dns: host2, addrs: etcHostsMap[host2]},
				{dns: wsHost, addrs: etcHostsMap[wsHost]},
			},
			-1,
		},
		{
			"Should remove all(>1) dns records after expiration",
			[]testRecord{
				{dns: host2, addrs: etcHostsMap[host]},
				{dns: host2, addrs: etcHostsMap[host2]},
				{dns: host2, addrs: etcHostsMap[wsHost]},
			},
			time.Duration(expiration+10) * time.Millisecond,
			[]testRecord{},
			checkInterval,
		},
		{
			"Should remove only expired record after expiration",
			[]testRecord{
				{dns: host, addrs: etcHostsMap[host]},
				{dns: host2, addrs: etcHostsMap[host2], addDelay: 500 * time.Millisecond},
				{dns: wsHost, addrs: etcHostsMap[wsHost]},
			},
			time.Duration(expiration-400) * time.Millisecond,
			[]testRecord{
				{dns: host2, addrs: etcHostsMap[host2]},
				{dns: wsHost, addrs: etcHostsMap[wsHost]},
			},
			checkInterval,
		},
		{
			"Should remove only expired records after expiration",
			[]testRecord{
				{dns: host, addrs: etcHostsMap[host]},
				{dns: host2, addrs: etcHostsMap[host2], addDelay: 250 * time.Millisecond},
				{dns: host3, addrs: etcHostsMap[host3], addDelay: 500 * time.Millisecond},
				{dns: host4, addrs: etcHostsMap[host4], addDelay: 100 * time.Millisecond},
				{dns: wsHost, addrs: etcHostsMap[wsHost]},
			},
			time.Duration(expiration-350) * time.Millisecond,
			[]testRecord{
				{dns: host3, addrs: etcHostsMap[host3]},
				{dns: host4, addrs: etcHostsMap[host4]},
				{dns: wsHost, addrs: etcHostsMap[wsHost]},
			},
			checkInterval,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dnsCache := NewDnsCacheStorage(time.Duration(expiration)*time.Millisecond, time.Duration(tc.checkInterval)*time.Millisecond)

			for _, r := range tc.records {
				if r.addDelay > 0 {
					time.Sleep(r.addDelay)
				}
				dnsCache.Set(r.dns, r.addrs)
			}

			if tc.sleepBeforeCleanup > 0 {
				time.Sleep(tc.sleepBeforeCleanup)
			}
			if lenNonExpired, lenCurrent := len(tc.notExpiredAfterDelay), len(dnsCache.Items(tc.checkInterval == -1)); lenNonExpired != lenCurrent {
				t.Fatalf("wanted len(nonExpiredItems) %d, got %d. items=%+v", lenNonExpired, lenCurrent, dnsCache.Items(tc.checkInterval == -1))
			}

			if tc.checkInterval == -1 {
				for _, r := range tc.records {
					if item, ok := dnsCache.Items(true)[r.dns]; !ok || !test.IsDnsRecordsAddrsEqualsTo(item.Addrs, r.addrs) {
						t.Fatalf("wanted expired cached ips %v, got item %#v. items=%+v, ok=%t", r.addrs, item, dnsCache.Items(true), ok)
					}
				}
			} else {
				for _, r := range tc.notExpiredAfterDelay {
					if item, ok := dnsCache.Get(r.dns); !ok || !test.IsDnsRecordsAddrsEqualsTo(item.Addrs, r.addrs) {
						t.Fatalf("wanted cached ips %v, got item %#v. items=%+v, ok=%t", r.addrs, item, dnsCache.Items(false), ok)
					}
				}
			}

			dnsCache.Clear()
			dnsCache = nil
		})
	}
}
