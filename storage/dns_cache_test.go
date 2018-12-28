package storage

import (
	"net"
	"net/http"
	"testing"
)

var (
	updateInterval = 5 * time.Second
)

func TestStorageFetchItem(t *testing.T) {
	dnsCache := storage.NewDnsCacheStorage(time.Duration(updateInterval))

	const (
		host = "orig-host.com"
		host2 = "orig-host2.com"
		wshost = "ws.orig-host.com"
	)

	var (
		etcHostsMap = map[string][]net.IP {
			host: []net.IP{ net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 2), },
			host2: []net.IP{ net.IPv4(10, 0, 2, 0), net.IPv4(10,0,2,1), net.IPv4(10,0,2,2), },
			wsHost: []net.IP{ net.IPv4(127, 0, 0, 1), net.IPv4(127,0,0,1) },
		}
	)


	cases := []struct {
		name string

		Host     string
		IPs     []net.IP

		shouldBeCached bool
	}{
		{
			"Should cache first dns record first fetch",
			host, etcHostsMap[host]
			true,
		},
		{
			"Should cache second dns record first fetch",
			host2, etcHostsMap[host2]
			true,
		},
		{
			"Should populate from cache first dns record second fetch",
			host, etcHostsMap[host]
			false,
		},
		},
		{
			"Should populate from cache first dns record third fetch",
			host, etcHostsMap[host]
			false,
		},
		},
		{
			"Should populate from cache second dns record second fetch",
			host2, etcHostsMap[host2]
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			
			got, err := dnsCache.FetchRecord(tc.host)

			if err != nil || !reflect.DeepEqual(got, tc.IPs) {
				t.Fatalf("wanted ips %q, got %q. Error: %v", tc.IPs, got, err)
			}

			record, ok  := dnsCache.Get(tc.host)

			if tc.shouldBeCached {
				if !ok  {
					t.Fatalf("Hosts address wasn't cached; host %q", tc.host)
				}
			} 

			if !record || !record.IsEqualsTo(tc.IPs) {
				t.Fatalf("wanted cached ips %q, got %q", tc.IPs, record) //TODO: Check whether $v is needed
			}			
		})
	}
}

func TestStorageRemoveRecordAfterExpiration(t *testing.T) {
	//TODO: Check of expired and not expired records
	dnsCache := storage.NewDnsCacheStorage(time.Duration(updateInterval))	
}