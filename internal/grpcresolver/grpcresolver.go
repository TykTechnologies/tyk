// Package grpcresolver adapts the gateway's DNS discovery scheduler to grpc-go's
// naming API, so a gRPC client rediscovers pods on a timer instead of only when a
// connection breaks.
//
// grpc-go's own DNS resolver re-resolves only when ResolveNow is called, which
// happens when a connection attempt fails or an established connection is lost.
// A scale-up is neither, so the new pods never receive traffic.
//
// The scheduler is the one that serves upstream DNS discovery. Entries are keyed
// by hostname, so a plugin Service that is also an upstream costs one lookup per
// interval.
package grpcresolver

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/resolver"

	"github.com/TykTechnologies/tyk/internal/dnsdiscovery"
)

// Scheme is the target scheme this resolver claims. A target must be written as
// "tykdns:///host:port" for the builder to be consulted.
const Scheme = "tykdns"

// Target renders a host:port endpoint as a dial target for this resolver.
func Target(endpoint string) string {
	return Scheme + ":///" + endpoint
}

// Subscriber is the part of dnsdiscovery.Scheduler the resolver uses.
type Subscriber interface {
	Subscribe(ctx context.Context, key string, cfg dnsdiscovery.Config) (*dnsdiscovery.Subscription, error)
	Warm(ctx context.Context) []string
}

// Builder builds resolvers backed by a shared scheduler. Register it per client
// with grpc.WithResolvers rather than globally.
type Builder struct {
	// Scheduler performs and caches the lookups.
	Scheduler Subscriber

	// Key identifies the subscription on the scheduler. It must not collide with
	// any other subscriber's key, since a second Subscribe on a key supersedes
	// the first.
	Key string

	// Interval is the refresh interval requested for the hostname.
	Interval time.Duration

	// WarmTimeout bounds the synchronous first lookup in Build. Zero skips it.
	WarmTimeout time.Duration

	// Ctx bounds the scheduler's refresh loop. Nil means context.Background.
	Ctx context.Context
}

// Scheme implements resolver.Builder.
func (b *Builder) Scheme() string { return Scheme }

// Build implements resolver.Builder. The endpoint must be a host:port.
func (b *Builder) Build(target resolver.Target, cc resolver.ClientConn, _ resolver.BuildOptions) (resolver.Resolver, error) {
	endpoint := target.Endpoint()

	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("grpcresolver: target %q is not host:port: %w", endpoint, err)
	}

	// An IP literal or localhost has nothing to discover. Report it once and
	// hand back a resolver that owns no subscription.
	if !dnsdiscovery.Resolvable(host) {
		if err := cc.UpdateState(stateFor([]string{host}, port)); err != nil {
			return nil, err
		}
		return noopResolver{}, nil
	}

	ctx := b.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	r := &schedulerResolver{cc: cc, host: host, port: port}

	sub, err := b.Scheduler.Subscribe(ctx, b.Key, dnsdiscovery.Config{
		Host:     host,
		Interval: b.Interval,
		OnChange: r.publish,
	})
	if err != nil {
		return nil, err
	}
	r.sub = sub

	// Resolve once before returning, so the first RPC does not wait for the
	// scheduler's next pass.
	if sub.State() == nil && b.WarmTimeout > 0 {
		warmCtx, cancel := context.WithTimeout(ctx, b.WarmTimeout)
		b.Scheduler.Warm(warmCtx)
		cancel()
	}

	if !r.published.Load() {
		cc.ReportError(fmt.Errorf("grpcresolver: no addresses for %q yet", host))
	}

	return r, nil
}

type schedulerResolver struct {
	cc   resolver.ClientConn
	host string
	port string
	sub  *dnsdiscovery.Subscription

	published atomic.Bool
}

// publish hands a usable address set to the ClientConn.
//
// An empty set is never forwarded. The scheduler publishes one after NXDOMAIN or
// repeated empty answers, and grpc-go's balancer removes every child absent from
// an incoming set before it decides whether to reject that set, so forwarding it
// tears down every healthy connection and fails every API with a gRPC plugin.
// Withholding it leaves the client on the last good set. Plugins have no
// stale_ttl.
func (r *schedulerResolver) publish(state *dnsdiscovery.State) {
	if !state.Usable() {
		if !r.published.Load() {
			r.cc.ReportError(fmt.Errorf("grpcresolver: %q: %s", r.host, state.Outcome))
		}
		return
	}

	if err := r.cc.UpdateState(stateFor(state.Addrs, r.port)); err != nil {
		r.cc.ReportError(err)
		return
	}
	r.published.Store(true)
}

// ResolveNow is a no-op: the scheduler already refreshes, and honouring the
// hint would let a flapping connection drive DNS query volume.
func (r *schedulerResolver) ResolveNow(resolver.ResolveNowOptions) {}

// Close releases the subscription. The scheduler stops resolving the hostname
// once no subscriber is left.
func (r *schedulerResolver) Close() { r.sub.Release() }

type noopResolver struct{}

func (noopResolver) ResolveNow(resolver.ResolveNowOptions) {}
func (noopResolver) Close()                                {}

// stateFor renders addresses as resolver state.
//
// Endpoints is the field that matters. The round_robin policy is built on
// endpointsharding, which iterates State.Endpoints and never reads
// State.Addresses, so a resolver that only fills Addresses produces exactly one
// child and no balancing at all. Addresses is filled too, for policies that
// still read it.
func stateFor(addresses []string, port string) resolver.State {
	state := resolver.State{
		Addresses: make([]resolver.Address, 0, len(addresses)),
		Endpoints: make([]resolver.Endpoint, 0, len(addresses)),
	}
	for _, addr := range addresses {
		a := resolver.Address{Addr: net.JoinHostPort(addr, port)}
		state.Addresses = append(state.Addresses, a)
		state.Endpoints = append(state.Endpoints, resolver.Endpoint{Addresses: []resolver.Address{a}})
	}
	return state
}
