package grpcresolver

import (
	"context"
	"net"
	"net/url"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/resolver"

	"github.com/TykTechnologies/tyk/internal/dnsdiscovery"
)

type fakeDNS struct {
	mu    sync.Mutex
	addrs []string
	err   error
}

func (f *fakeDNS) set(addrs []string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addrs, f.err = addrs, err
}

func (f *fakeDNS) lookup(context.Context, string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.addrs...), f.err
}

type fakeClientConn struct {
	resolver.ClientConn

	mu      sync.Mutex
	updates []resolver.State
	errors  []error
}

func (c *fakeClientConn) UpdateState(s resolver.State) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.updates = append(c.updates, s)
	return nil
}

func (c *fakeClientConn) ReportError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errors = append(c.errors, err)
}

func (c *fakeClientConn) snapshot() ([]resolver.State, []error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]resolver.State(nil), c.updates...), append([]error(nil), c.errors...)
}

func endpoints(s resolver.State) []string {
	out := make([]string, 0, len(s.Endpoints))
	for _, e := range s.Endpoints {
		out = append(out, e.Addresses[0].Addr)
	}
	sort.Strings(out)
	return out
}

func newBuilder(t *testing.T, dns *fakeDNS) (*Builder, *dnsdiscovery.Scheduler) {
	t.Helper()
	sched := &dnsdiscovery.Scheduler{Lookup: dns.lookup}
	return &Builder{
		Scheduler:   sched,
		Key:         "coprocess:grpc",
		Interval:    time.Hour,
		WarmTimeout: time.Second,
		Ctx:         t.Context(),
	}, sched
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

func build(t *testing.T, b *Builder, endpoint string) (*fakeClientConn, resolver.Resolver) {
	t.Helper()
	cc := &fakeClientConn{}
	r, err := b.Build(resolver.Target{URL: *mustParse(t, Target(endpoint))}, cc, resolver.BuildOptions{})
	require.NoError(t, err)
	t.Cleanup(r.Close)
	return cc, r
}

func TestBuild_PublishesEveryAddressBeforeReturning(t *testing.T) {
	dns := &fakeDNS{addrs: []string{"10.0.0.2", "10.0.0.1"}}
	b, _ := newBuilder(t, dns)

	cc, _ := build(t, b, "plugin.test:9001")

	updates, errs := cc.snapshot()
	require.Len(t, updates, 1)
	assert.Empty(t, errs)
	assert.Equal(t, []string{"10.0.0.1:9001", "10.0.0.2:9001"}, endpoints(updates[0]))
}

func TestBuild_NoAnswerReportsError(t *testing.T) {
	dns := &fakeDNS{err: &net.DNSError{Err: "timeout", IsTimeout: true}}
	b, _ := newBuilder(t, dns)

	cc, _ := build(t, b, "plugin.test:9001")

	updates, errs := cc.snapshot()
	assert.Empty(t, updates)
	assert.NotEmpty(t, errs)
}

func TestPublish_NeverForwardsAnEmptySet(t *testing.T) {
	cases := map[string]error{
		"empty answer": nil,
		"NXDOMAIN":     &net.DNSError{Err: "no such host", IsNotFound: true},
		"timeout":      &net.DNSError{Err: "timeout", IsTimeout: true},
	}

	for name, lookupErr := range cases {
		t.Run(name, func(t *testing.T) {
			dns := &fakeDNS{addrs: []string{"10.0.0.1", "10.0.0.2"}}
			b, sched := newBuilder(t, dns)
			cc, _ := build(t, b, "plugin.test:9001")

			dns.set(nil, lookupErr)
			for i := 0; i < dnsdiscovery.EmptyAnswerThreshold+1; i++ {
				sched.Refresh(t.Context())
			}

			updates, _ := cc.snapshot()
			for _, u := range updates {
				assert.NotEmpty(t, u.Endpoints, "an empty address set reached the ClientConn")
			}
			assert.Equal(t, []string{"10.0.0.1:9001", "10.0.0.2:9001"}, endpoints(updates[len(updates)-1]))
		})
	}
}

func TestPublish_ForwardsScaleUpAndScaleDown(t *testing.T) {
	dns := &fakeDNS{addrs: []string{"10.0.0.1", "10.0.0.2"}}
	b, sched := newBuilder(t, dns)
	cc, _ := build(t, b, "plugin.test:9001")

	dns.set([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}, nil)
	sched.Refresh(t.Context())

	dns.set([]string{"10.0.0.3", "10.0.0.4"}, nil)
	sched.Refresh(t.Context())

	updates, _ := cc.snapshot()
	require.Len(t, updates, 3)
	assert.Len(t, updates[1].Endpoints, 4)
	assert.Equal(t, []string{"10.0.0.3:9001", "10.0.0.4:9001"}, endpoints(updates[2]))
}

func TestBuild_SharesLookupsWithOtherSubscribers(t *testing.T) {
	dns := &fakeDNS{addrs: []string{"10.0.0.1"}}
	b, sched := newBuilder(t, dns)

	_, err := sched.Subscribe(t.Context(), "some-api-id", dnsdiscovery.Config{Host: "plugin.test", Interval: time.Hour})
	require.NoError(t, err)
	sched.Warm(t.Context())
	before := sched.Lookups()

	cc, _ := build(t, b, "plugin.test:9001")

	updates, _ := cc.snapshot()
	require.Len(t, updates, 1, "a warm hostname is delivered on Subscribe")
	assert.Equal(t, before, sched.Lookups(), "the plugin subscription should reuse the upstream's lookup")
}

func TestClose_ReleasesTheHostname(t *testing.T) {
	dns := &fakeDNS{addrs: []string{"10.0.0.1"}}
	b, sched := newBuilder(t, dns)
	_, r := build(t, b, "plugin.test:9001")

	r.Close()
	before := sched.Lookups()
	sched.Refresh(t.Context())

	assert.Equal(t, before, sched.Lookups(), "a released hostname is still being resolved")
}

func TestBuild_IPLiteralAndLocalhostAreNotResolved(t *testing.T) {
	for _, endpoint := range []string{"10.0.0.9:9001", "localhost:9001"} {
		t.Run(endpoint, func(t *testing.T) {
			dns := &fakeDNS{addrs: []string{"10.0.0.1"}}
			b, sched := newBuilder(t, dns)

			cc, _ := build(t, b, endpoint)

			updates, _ := cc.snapshot()
			require.Len(t, updates, 1)
			assert.Equal(t, []string{endpoint}, endpoints(updates[0]))
			assert.Zero(t, sched.Lookups())
		})
	}
}
