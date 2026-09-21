package dnsdiscovery

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultInterval = 30 * time.Second
	MinInterval     = 5 * time.Second

	// Applied by callers, since zero here means never.
	DefaultStaleTTL = 300 * time.Second

	LookupTimeout = 5 * time.Second
	MaxBackoff    = 5 * time.Minute

	// Added at random per cycle, so gateways do not resolve in lockstep.
	JitterFraction = 0.1

	// Bounds a missed wake, with no name registered.
	idleWait = time.Minute

	// Keeps a pathological interval from busy-waiting.
	minWait = 10 * time.Millisecond

	maxConcurrentLookups = 8
)

// LookupFunc resolves a host to a set of addresses.
type LookupFunc func(ctx context.Context, host string) ([]string, error)

// Config is what one subscriber asks for.
type Config struct {
	// Host is the DNS name to resolve, without a port.
	Host string

	// Zero means DefaultInterval. No floor here; see NormaliseInterval.
	Interval time.Duration

	// Bounds the last known good set. Zero means never give up.
	StaleTTL time.Duration

	// Runs unlocked, must not block, and is skipped when nothing changed.
	OnChange func(*State)
}

// Scheduler refreshes names in the background, one entry per distinct name.
// The zero value is ready to use, and its goroutine runs from the first
// subscription until that subscription's context is cancelled.
type Scheduler struct {
	mu sync.Mutex

	// Keyed by hostname, and by subscriber key.
	entries map[string]*entry
	subs    map[string]*Subscription

	version uint64
	running bool
	wake    chan struct{}
	runCtx  context.Context

	// Injectable for tests, read by the refresh goroutine: set before the
	// first Subscribe.
	Lookup LookupFunc
	Now    func() time.Time
	Jitter func(time.Duration) time.Duration

	lookups atomic.Int64
}

// Shared by every subscriber on one name. All fields but published are
// guarded by the scheduler's mutex.
type entry struct {
	host string

	// Stops Refresh and the loop publishing out of order. Taken before mu.
	refreshMu sync.Mutex

	published atomic.Pointer[State]

	interval    time.Duration
	staleTTL    time.Duration
	nextDue     time.Time
	failures    int
	lastSuccess time.Time
	subs        map[*Subscription]struct{}
}

// Subscription is one subscriber's handle on a name.
type Subscription struct {
	key      string
	host     string
	interval time.Duration
	staleTTL time.Duration
	onChange func(*State)

	// Set once, so a superseded subscription goes on reporting the last set
	// it saw while its spec is still serving.
	entry *entry
	sched *Scheduler

	detached bool
}

// State returns the published address set, or nil before the first
// resolution. The returned pointer is never mutated.
func (s *Subscription) State() *State {
	if s == nil || s.entry == nil {
		return nil
	}
	return s.entry.published.Load()
}

// Host is the name this subscription resolves.
func (s *Subscription) Host() string {
	if s == nil {
		return ""
	}
	return s.host
}

// Release drops this subscription, and the entry when nothing else wants that
// name. One already superseded is ignored, so a late teardown hook cannot
// drop the live one.
func (s *Subscription) Release() {
	if s == nil || s.sched == nil {
		return
	}
	s.sched.release(s)
}

// NormaliseInterval applies the default and the floor.
func NormaliseInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return DefaultInterval
	}
	if interval < MinInterval {
		return MinInterval
	}
	return interval
}

// Subscribe points key at cfg.Host, moving a key already subscribed so that a
// reload supersedes rather than duplicates. Nothing is resolved here, since an
// inline lookup would put DNS on whatever path loads a subscriber.
func (s *Scheduler) Subscribe(ctx context.Context, key string, cfg Config) (*Subscription, error) {
	if cfg.Host == "" {
		return nil, ErrNoHost
	}

	interval := cfg.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}

	sub := &Subscription{
		key:      key,
		host:     cfg.Host,
		interval: interval,
		staleTTL: cfg.StaleTTL,
		onChange: cfg.OnChange,
		sched:    s,
	}

	s.mu.Lock()

	if s.entries == nil {
		s.entries = map[string]*entry{}
		s.subs = map[string]*Subscription{}
	}

	e, existing := s.entries[cfg.Host]
	if !existing {
		e = &entry{
			host:    cfg.Host,
			nextDue: s.timeNow(),
			subs:    map[*Subscription]struct{}{},
		}
		s.entries[cfg.Host] = e
	}

	sub.entry = e
	e.subs[sub] = struct{}{}

	// Attached before the one it supersedes is released, so a reload of a
	// name's only subscriber keeps the entry and its last good set.
	if previous, ok := s.subs[key]; ok {
		delete(s.subs, key)
		s.detachLocked(previous)
	}

	s.subs[key] = sub
	s.recomputeLocked(e)

	current := e.published.Load()

	s.ensureRunningLocked(ctx)
	s.mu.Unlock()

	// Or a subscriber joining a resolved name computes its first membership
	// change against an empty set.
	if current != nil && sub.onChange != nil {
		sub.onChange(current)
	}

	return sub, nil
}

// ReleaseKey is for subscribers reconciled rather than torn down.
func (s *Scheduler) ReleaseKey(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sub, ok := s.subs[key]
	if !ok {
		return
	}
	delete(s.subs, key)
	s.detachLocked(sub)
}

// Refresh resolves every registered name on the calling goroutine.
func (s *Scheduler) Refresh(ctx context.Context) {
	s.mu.Lock()
	all := make([]*entry, 0, len(s.entries))
	for _, e := range s.entries {
		all = append(all, e)
	}
	s.mu.Unlock()

	s.refreshAll(ctx, all)
}

// Lookups counts the lookups completed since the scheduler started.
func (s *Scheduler) Lookups() int64 {
	return s.lookups.Load()
}

func (s *Scheduler) timeNow() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Scheduler) resolve(ctx context.Context, host string) ([]string, error) {
	s.lookups.Add(1)

	// Wraps an injected resolver too, so a hanging stub cannot wedge a cycle.
	ctx, cancel := context.WithTimeout(ctx, LookupTimeout)
	defer cancel()

	if s.Lookup != nil {
		return s.Lookup(ctx, host)
	}

	return net.DefaultResolver.LookupHost(ctx, host)
}

func (s *Scheduler) nextInterval(base time.Duration) time.Duration {
	if s.Jitter != nil {
		return s.Jitter(base)
	}
	span := int64(float64(base) * JitterFraction)
	if base <= 0 || span <= 0 {
		return base
	}
	return base + time.Duration(rand.Int63n(span))
}

func (s *Scheduler) release(sub *Subscription) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if current, ok := s.subs[sub.key]; !ok || current != sub {
		return
	}
	delete(s.subs, sub.key)
	s.detachLocked(sub)
}

func (s *Scheduler) detachLocked(sub *Subscription) {
	e := sub.entry
	if e == nil || sub.detached {
		return
	}
	sub.detached = true

	delete(e.subs, sub)
	if len(e.subs) == 0 {
		delete(s.entries, e.host)
		return
	}
	s.recomputeLocked(e)
}

func (s *Scheduler) recomputeLocked(e *entry) {
	// One refresh serves everyone, so the shortest interval wins. Reaching
	// the stale TTL discards the addresses for everyone, so the longest wins
	// and a zero decides the entry.
	interval, staleTTL := time.Duration(0), time.Duration(0)
	unbounded := false
	for sub := range e.subs {
		if interval == 0 || sub.interval < interval {
			interval = sub.interval
		}
		switch {
		case sub.staleTTL <= 0:
			unbounded = true
		case sub.staleTTL > staleTTL:
			staleTTL = sub.staleTTL
		}
	}
	if unbounded {
		staleTTL = 0
	}

	e.staleTTL = staleTTL
	if interval == 0 || interval == e.interval {
		return
	}

	// A shortened interval pulls the next refresh in with it.
	if due := s.timeNow().Add(interval); interval < e.interval && due.Before(e.nextDue) {
		e.nextDue = due
	}
	e.interval = interval
}

func (s *Scheduler) ensureRunningLocked(ctx context.Context) {
	// A goroutine whose context is done may not have cleared running yet, and
	// waking it leaves the entries with nothing refreshing them. A nil runCtx
	// means the loop was suppressed, as tests do.
	if s.running && (s.runCtx == nil || s.runCtx.Err() == nil) {
		select {
		case s.wake <- struct{}{}:
		default:
		}
		return
	}

	s.running = true
	s.runCtx = ctx
	s.wake = make(chan struct{}, 1)
	go s.run(ctx, s.wake)
}

// Takes its own wake channel, so a replaced goroutine cannot clear the flag
// its replacement set.
func (s *Scheduler) run(ctx context.Context, wake chan struct{}) {
	defer func() {
		s.mu.Lock()
		if s.wake == wake {
			s.running = false
		}
		s.mu.Unlock()
	}()

	for {
		s.refreshAll(ctx, s.dueEntries())

		timer := time.NewTimer(s.nextWait())
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		case <-wake:
			timer.Stop()
		}
	}
}

func (s *Scheduler) refreshAll(ctx context.Context, due []*entry) {
	if len(due) <= 1 {
		if len(due) == 1 {
			s.refresh(ctx, due[0])
		}
		return
	}

	sem := make(chan struct{}, maxConcurrentLookups)
	var wg sync.WaitGroup
	for _, e := range due {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			s.refresh(ctx, e)
		}()
	}
	wg.Wait()
}

// Computed after the refresh pass, because an entry just refreshed holds the
// nearest deadline.
func (s *Scheduler) nextWait() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.entries) == 0 {
		return idleWait
	}

	now := s.timeNow()
	wait := time.Duration(-1)
	for _, e := range s.entries {
		remaining := e.nextDue.Sub(now)
		if remaining < 0 {
			remaining = 0
		}
		if wait < 0 || remaining < wait {
			wait = remaining
		}
	}

	if wait < minWait {
		wait = minWait
	}
	return wait
}

func (s *Scheduler) dueEntries() []*entry {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.timeNow()
	var due []*entry
	for _, e := range s.entries {
		if !e.nextDue.After(now) {
			due = append(due, e)
		}
	}
	return due
}

// A successful answer, with records or without, and an NXDOMAIN are applied
// as they stand. An unreachable resolver is not a fact about the name, so the
// addresses are kept and the entry backs off, bounded by the stale TTL.
func (s *Scheduler) refresh(ctx context.Context, e *entry) {
	// One at a time, or refreshes publish out of order.
	e.refreshMu.Lock()
	defer e.refreshMu.Unlock()

	addrs, err := s.resolve(ctx, e.host)
	addrs = Normalise(addrs)

	s.mu.Lock()

	base := e.interval
	if base <= 0 {
		base = DefaultInterval
	}

	var published *State
	var notify []func(*State)

	switch {
	case err == nil:
		e.failures = 0
		e.lastSuccess = s.timeNow()
		e.nextDue = s.timeNow().Add(s.nextInterval(base))

		if len(addrs) == 0 {
			published, notify = s.publishLocked(e, nil, Empty)
		} else {
			published, notify = s.publishLocked(e, addrs, Resolved)
		}

	default:
		e.failures++
		e.nextDue = s.timeNow().Add(s.backoffLocked(base, e.failures))

		switch {
		case isNameNotFound(err):
			published, notify = s.publishLocked(e, nil, NotFound)

		// Nothing published yet, so no stale set to bound.
		case e.published.Load() == nil:
			published, notify = s.publishLocked(e, nil, Unreachable)

		case e.staleTTL > 0 && !e.lastSuccess.IsZero() &&
			s.timeNow().Sub(e.lastSuccess) > e.staleTTL:
			published, notify = s.publishLocked(e, nil, Unreachable)
		}
	}

	s.mu.Unlock()

	// Off the lock, so a slow subscriber cannot delay other names.
	for _, onChange := range notify {
		onChange(published)
	}
}

func (s *Scheduler) publishLocked(e *entry, addrs []string, outcome Outcome) (*State, []func(*State)) {
	if current := e.published.Load(); current != nil &&
		current.Outcome == outcome && equalAddrs(current.Addrs, addrs) {
		return nil, nil
	}

	s.version++
	state := &State{Version: s.version, Addrs: addrs, Outcome: outcome}
	e.published.Store(state)

	var notify []func(*State)
	for sub := range e.subs {
		if sub.onChange != nil {
			notify = append(notify, sub.onChange)
		}
	}
	return state, notify
}

func (s *Scheduler) backoffLocked(base time.Duration, failures int) time.Duration {
	interval := base
	for i := 1; i < failures && interval < MaxBackoff; i++ {
		interval *= 2
	}
	if interval > MaxBackoff {
		interval = MaxBackoff
	}
	return s.nextInterval(interval)
}

func isNameNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
