package gateway

import (
	"net/url"
	"testing"
)

// TestUpstreamDNSLoadBalancing_SkipsTLSUpstreams pins the scheme guard.
//
// Rewriting a target to a pod address makes the transport dial an IP literal,
// and Go derives SNI and certificate verification from the URL host whenever
// tls.Config.ServerName is unset — which it always is here. A service
// certificate issued for the service name, with no IP SAN, then fails to
// verify, so every request to that API breaks. Verified out of band: dialling
// one listener by name verifies and by IP fails with "cannot validate
// certificate for <ip> because it doesn't contain any IP SANs".
//
// The feature is a gateway-wide switch, so it reaches every API, not only the
// gRPC ones it was designed for. That makes this guard load-bearing rather than
// defensive.
func TestUpstreamDNSLoadBalancing_SkipsTLSUpstreams(t *testing.T) {
	cases := []struct {
		scheme  string
		wantTLS bool
	}{
		{"h2c", false},
		{"http", false},
		{"ws", false},
		{"https", true},
		{"HTTPS", true},
		{"wss", true},
		{"tls", true},
	}

	for _, tc := range cases {
		if got := tlsUpstreamScheme(tc.scheme); got != tc.wantTLS {
			t.Errorf("tlsUpstreamScheme(%q) = %v, want %v", tc.scheme, got, tc.wantTLS)
		}
	}
}

// TestSplitUpstreamHostPort covers the default ports, which have to be supplied
// explicitly because the poller resolves a bare name and gets bare addresses
// back with no port attached.
func TestSplitUpstreamHostPort(t *testing.T) {
	cases := []struct {
		raw        string
		host, port string
	}{
		{"h2c://svc:9002", "svc", "9002"},
		{"h2c://svc", "svc", "80"},
		{"http://svc", "svc", "80"},
		{"https://svc", "svc", "443"},
		{"http://svc:8080/base", "svc", "8080"},
	}

	for _, tc := range cases {
		u, err := url.Parse(tc.raw)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.raw, err)
		}
		host, port := splitUpstreamHostPort(u)
		if host != tc.host || port != tc.port {
			t.Errorf("splitUpstreamHostPort(%q) = (%q, %q), want (%q, %q)",
				tc.raw, host, port, tc.host, tc.port)
		}
	}
}

// TestPollableHost checks what is worth starting a goroutine for. An IP literal
// resolves to itself forever, and localhost is not a Service.
func TestPollableHost(t *testing.T) {
	cases := map[string]bool{
		"upstream":                 true,
		"svc.ns.svc.cluster.local": true,
		"10.0.0.1":                 false,
		"::1":                      false,
		"localhost":                false,
		"LOCALHOST":                false,
		"":                         false,
	}

	for host, want := range cases {
		if got := pollableHost(host); got != want {
			t.Errorf("pollableHost(%q) = %v, want %v", host, got, want)
		}
	}
}

// TestBuildUpstreamTarget checks that the scheme survives.
//
// This is the point of the EnsureTransport change: the h2c transport is chosen
// from the request scheme after the Director has run, so an entry written as
// http:// here would reach a gRPC upstream over HTTP/1.1.
func TestBuildUpstreamTarget(t *testing.T) {
	cases := []struct {
		raw, addr, port, want string
	}{
		{"h2c://svc:9002", "10.0.0.1", "9002", "h2c://10.0.0.1:9002"},
		{"http://svc:8080", "10.0.0.2", "8080", "http://10.0.0.2:8080"},
		{"h2c://svc:9002/base", "10.0.0.3", "9002", "h2c://10.0.0.3:9002/base"},
		{"h2c://svc:9002/", "10.0.0.4", "9002", "h2c://10.0.0.4:9002"},
	}

	for _, tc := range cases {
		u, err := url.Parse(tc.raw)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.raw, err)
		}
		if got := buildUpstreamTarget(u, tc.addr, tc.port); got != tc.want {
			t.Errorf("buildUpstreamTarget(%q, %q) = %q, want %q", tc.raw, tc.addr, got, tc.want)
		}
	}
}
