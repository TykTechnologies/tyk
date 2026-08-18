// Package grpcresolver adapts internal/dnspoll to grpc-go's naming API, so a
// gRPC client rediscovers pods on a timer instead of only when a connection
// breaks.
//
// grpc-go's own DNS resolver blocks after a successful lookup and re-resolves
// only when ResolveNow is called, which happens in exactly two situations: a
// connection attempt fails, or an established connection is lost. A scale-up is
// neither. Every existing connection stays healthy, nothing fails, ResolveNow is
// never called, and the new pods sit idle indefinitely.
//
// Wrapping that resolver rather than replacing it does not work. Its
// MinResolutionInterval is a process-global 30 s floor on the interval between
// successful lookups, so any shorter interval is silently ignored; it publishes
// an empty address set on NXDOMAIN, which is the one thing that must not happen
// (see dnspoll.Poller); and it shares nothing with the reverse-proxy path, which
// has no resolver concept at all. Replacing it also fails loudly rather than
// silently on a grpc-go upgrade, because this package depends only on interface
// methods and struct fields.
package grpcresolver

import (
	"context"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc/resolver"

	"github.com/TykTechnologies/tyk/internal/dnspoll"
)

// Scheme is the target scheme this resolver claims. A target must be written as
// "tykdns:///host:port" for the builder to be consulted.
const Scheme = "tykdns"

// Target renders a host:port endpoint as a dial target for this resolver.
func Target(endpoint string) string {
	return Scheme + ":///" + endpoint
}

// Builder builds polling resolvers. Register it per client with
// grpc.WithResolvers rather than globally, so the interval is a property of the
// client that asked for it.
type Builder struct {
	// Interval is the poll interval. Zero means dnspoll.DefaultInterval.
	Interval time.Duration

	// Lookup overrides address resolution. Nil means the system resolver. Used
	// by tests.
	Lookup dnspoll.LookupFunc

	// Ctx bounds the lifetime of every poller this builder starts. Nil means
	// context.Background, in which case pollers are stopped only by
	// Resolver.Close.
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

	// An IP literal resolves to itself forever. Report it once and hand back a
	// resolver that owns no goroutine and no timer.
	if ip := net.ParseIP(host); ip != nil {
		if err := cc.UpdateState(stateFor([]string{host}, port)); err != nil {
			return nil, err
		}
		return noopResolver{}, nil
	}

	r := &pollingResolver{cc: cc, port: port}

	poller, err := dnspoll.New(dnspoll.Config{
		Host:     host,
		Interval: b.Interval,
		Lookup:   b.Lookup,
		OnChange: r.publish,
	})
	if err != nil {
		return nil, err
	}
	r.poller = poller

	ctx := b.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// Start resolves once synchronously, so a client has addresses before its
	// first RPC rather than after the first tick.
	poller.Start(ctx)

	// A first lookup that found nothing leaves the client with no addresses.
	// Say so: the alternative is an RPC blocking until the next tick with no
	// indication of why.
	if len(poller.Addresses()) == 0 {
		cc.ReportError(fmt.Errorf("grpcresolver: no addresses for %q yet", host))
	}

	return r, nil
}

type pollingResolver struct {
	cc     resolver.ClientConn
	port   string
	poller *dnspoll.Poller
}

// publish hands a new address set to the ClientConn.
//
// It is only ever called with a non-empty set, because dnspoll.Poller holds the
// last-good set on failure and never reports an empty one. That is load-bearing
// here rather than merely tidy: grpc-go's balancer removes the children absent
// from an incoming set before it decides whether to reject that set, so an
// empty-but-successful update tears down every healthy subconnection. For the
// plugin dispatcher that means every API carrying a plugin starts returning 500.
func (r *pollingResolver) publish(addresses []string) {
	if err := r.cc.UpdateState(stateFor(addresses, r.port)); err != nil {
		r.cc.ReportError(err)
	}
}

// ResolveNow is a no-op: this resolver already polls, and honouring the hint
// would let a flapping connection drive DNS query volume.
func (r *pollingResolver) ResolveNow(resolver.ResolveNowOptions) {}

// Close stops the poller and waits for its goroutine, so a closed client does
// not leave a ticker behind.
func (r *pollingResolver) Close() { r.poller.Stop() }

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
