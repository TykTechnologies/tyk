// Package dnspoll polls a DNS name on a fixed interval and reports membership
// changes in the set of addresses it resolves to.
//
// It exists because neither of the gateway's two gRPC paths rediscovers pods on
// its own. grpc-go's built-in DNS resolver only re-resolves when a connection
// attempt fails or an established connection is lost, so a scale-up — where
// nothing fails — is never noticed. The reverse-proxy path has no resolver
// concept at all. Polling makes discovery latency a function of the configured
// interval rather than of connection failure, which is the property both paths
// need.
//
// The package deals in strings and timers only: no gRPC types, no HTTP types.
// Each consumer adapts it to its own world — a resolver.Builder for the plugin
// path, a host-list updater for the upstream path.
package dnspoll

import (
	"context"
	"errors"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	// DefaultInterval is used when Config.Interval is not set.
	DefaultInterval = 30 * time.Second

	// DefaultTimeout bounds a single lookup. Without it a resolver that hangs
	// stalls the loop indefinitely and discovery stops.
	DefaultTimeout = 5 * time.Second

	// maxBackoff caps the failure backoff. Unbounded growth would leave
	// discovery broken long after DNS recovered.
	maxBackoff = 5 * time.Minute
)

// LookupFunc resolves a host to a set of addresses.
type LookupFunc func(ctx context.Context, host string) ([]string, error)

// Config configures a Poller. Host is the only required field.
type Config struct {
	// Host is the DNS name to poll, without a port.
	Host string

	// Interval is the time between successful lookups. Zero means
	// DefaultInterval.
	Interval time.Duration

	// Timeout bounds a single lookup. Zero means DefaultTimeout.
	Timeout time.Duration

	// Lookup resolves Host. Nil means net.DefaultResolver.LookupHost.
	Lookup LookupFunc

	// OnChange is called whenever the resolved set changes, with the new set.
	// It is called from the polling goroutine, so it must not block for long.
	// It is never called with an empty set — see Poller for why.
	OnChange func([]string)
}

// Poller resolves a name on a timer and calls Config.OnChange when the set of
// addresses changes.
//
// It never publishes an empty address set. A lookup that fails, or that
// succeeds with no addresses, leaves the last known-good set in place and does
// not call OnChange. This matters more than it looks: grpc-go's balancer
// removes the children absent from an incoming address set before it decides
// whether to reject that set, so an empty-but-successful update tears down every
// healthy connection. On the plugin path that means every API carrying a plugin
// starts returning 500; on the upstream path it fails every request to the API.
// Stale-but-working beats empty-and-correct.
type Poller struct {
	cfg Config

	mu        sync.RWMutex
	addresses []string

	startOnce sync.Once
	stopOnce  sync.Once
	cancel    context.CancelFunc
	done      chan struct{}
}

// New validates cfg and returns a Poller. It does not resolve anything; call
// Start for that.
func New(cfg Config) (*Poller, error) {
	if cfg.Host == "" {
		return nil, errors.New("dnspoll: Host is required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Lookup == nil {
		cfg.Lookup = func(ctx context.Context, host string) ([]string, error) {
			return net.DefaultResolver.LookupHost(ctx, host)
		}
	}
	return &Poller{cfg: cfg, done: make(chan struct{})}, nil
}

// Start resolves once synchronously, so a caller has addresses before the first
// tick, then polls in the background until ctx is cancelled or Stop is called.
// Calling Start more than once is a no-op.
func (p *Poller) Start(ctx context.Context) {
	p.startOnce.Do(func() {
		ctx, p.cancel = context.WithCancel(ctx)
		p.resolve()
		go p.loop(ctx)
	})
}

// Stop cancels the poll loop and waits for its goroutine to exit, so an
// unloaded API does not leave a ticker behind. It is safe to call more than
// once, and safe to call on a Poller that was never started.
func (p *Poller) Stop() {
	p.stopOnce.Do(func() {
		// Claim the start slot. If Start never ran this makes it a no-op, so a
		// Start after a Stop cannot resurrect the poller and there is no
		// goroutine to wait for. If Start did run, Do returns immediately and
		// its write to p.cancel is visible here.
		neverStarted := false
		p.startOnce.Do(func() { neverStarted = true })
		if neverStarted {
			close(p.done)
			return
		}

		p.cancel()
		<-p.done
	})
}

// Addresses returns the current known-good set. The returned slice is a copy.
func (p *Poller) Addresses() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	out := make([]string, len(p.addresses))
	copy(out, p.addresses)
	return out
}

func (p *Poller) loop(ctx context.Context) {
	defer close(p.done)

	// Backoff applies to lookup failures only. Backing off because nothing
	// changed would delay discovery of exactly the event this package exists to
	// catch, so a successful lookup always schedules the next one an Interval
	// away regardless of whether the set moved.
	backoff := time.Duration(0)

	for {
		wait := p.cfg.Interval
		if backoff > 0 {
			wait = backoff
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		if err := p.resolve(); err != nil {
			backoff = nextBackoff(backoff, p.cfg.Interval)
			continue
		}
		backoff = 0
	}
}

// resolve performs one lookup and publishes the result if the set changed.
func (p *Poller) resolve() error {
	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.Timeout)
	defer cancel()

	addrs, err := p.cfg.Lookup(ctx, p.cfg.Host)
	if err != nil {
		return err
	}

	addrs = normalise(addrs)
	if len(addrs) == 0 {
		// A successful lookup that returned nothing is treated exactly like a
		// failure: hold the last-good set rather than publish an empty one.
		return errors.New("dnspoll: lookup returned no addresses for " + p.cfg.Host)
	}

	p.mu.Lock()
	changed := !equal(p.addresses, addrs)
	if changed {
		p.addresses = addrs
	}
	p.mu.Unlock()

	if changed && p.cfg.OnChange != nil {
		out := make([]string, len(addrs))
		copy(out, addrs)
		p.cfg.OnChange(out)
	}
	return nil
}

// normalise sorts and de-duplicates, so that a resolver shuffling its answers —
// which CoreDNS's loadbalance plugin does by default — is not mistaken for a
// membership change.
func normalise(addrs []string) []string {
	if len(addrs) == 0 {
		return nil
	}

	out := make([]string, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		if a == "" {
			continue
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func nextBackoff(current, base time.Duration) time.Duration {
	if current <= 0 {
		current = base
	} else {
		current *= 2
	}
	if current > maxBackoff {
		current = maxBackoff
	}
	return current
}
