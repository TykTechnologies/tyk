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
	// DefaultInterval is used when a subscription asks for no interval.
	DefaultInterval = 30 * time.Second

	// MinInterval is the floor NormaliseInterval applies.
	MinInterval = 5 * time.Second

	// DefaultStaleTTL bounds how long a last known good set is kept while the
	// resolver is unreachable. Applied by callers, since zero means never.
	DefaultStaleTTL = 300 * time.Second

	// LookupTimeout bounds one lookup, so a resolver that hangs does not stall
	// the cycle it is part of.
	LookupTimeout = 5 * time.Second

	// MaxBackoff caps the interval after repeated failures, so discovery is not
	// left broken long after DNS recovers.
	MaxBackoff = 5 * time.Minute

	// JitterFraction is the proportion of the interval added at random to each
	// cycle, so that schedulers started together do not resolve in lockstep.
	JitterFraction = 0.1

	// idleWait is how long the loop sleeps with no name registered. A
	// subscription wakes it, so this only bounds a missed wake.
	idleWait = time.Minute

	// minWait floors the sleep between cycles, so a pathological interval
	// cannot turn the loop into a busy wait.
	minWait = 10 * time.Millisecond

	// maxConcurrentLookups bounds how many names resolve at once. Serially, a
	// few unreachable names would delay every healthy one behind them.
	maxConcurrentLookups = 8
)

// LookupFunc resolves a host to a set of addresses.
type LookupFunc func(ctx context.Context, host string) ([]string, error)

// Config is what one subscriber asks for.
type Config struct {
	// Host is the DNS name to resolve, without a port.
	Host string

	// Interval is how often Host is re-resolved. Zero means DefaultInterval.
	// No floor is applied; a caller exposing this as configuration passes it
	// through NormaliseInterval first.
	Interval time.Duration

	// StaleTTL bounds how long the last known good set is kept while the
	// resolver is unreachable. Zero means never give up on it.
	StaleTTL time.Duration

	// OnChange is called with the current state on Subscribe and with each
	// newly published one after that, with no lock held, so it must not block
	// for long. It is not called when a resolution changes nothing.
	OnChange func(*State)
}

// Scheduler refreshes names in the background, one entry per distinct name.
//
// The zero value is ready to use. The goroutine starts with the first
// subscription and stops when that subscription's context is cancelled.
type Scheduler struct {
	mu sync.Mutex

	// entries is keyed by hostname, subs by subscriber key, so a reload can
	// move a subscriber from one name to another or drop it.
	entries map[string]*entry
	subs    map[string]*Subscription

	version uint64
	running bool
	wake    chan struct{}
	runCtx  context.Context

	// Injectable for tests. Nil means the real implementation.
	//
	// Read from the refresh goroutine, so they must be set before the first
	// Subscribe and not touched afterwards.
	Lookup LookupFunc
	Now    func() time.Time
	Jitter func(time.Duration) time.Duration

	lookups atomic.Int64
}

// entry is the state for one name, shared by every subscriber pointing at it.
// All fields but published are guarded by the scheduler's mutex.
type entry struct {
	host string

	// refreshMu serialises refresh for this name, so Refresh and the loop
	// cannot publish out of order. Always taken before the scheduler mutex.
	refreshMu sync.Mutex

	// published is read by subscribers and written only by the scheduler.
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

	// entry is set once and never cleared, so a superseded subscription goes
	// on reporting the last set it saw — which the spec it belongs to still
	// needs while it is serving.
	entry *entry
	sched *Scheduler

	// detached is guarded by the scheduler mutex.
	detached bool
}

// State returns the currently published address set, or nil before the first
// resolution has completed. The returned pointer is never mutated.
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

// Release drops this subscription, and the shared entry with it when nothing
// else wants that name. A subscription already superseded under its key is
// ignored, so a late teardown hook cannot drop the live one.
func (s *Subscription) Release() {
	if s == nil || s.sched == nil {
		return
	}
	s.sched.release(s)
}

// NormaliseInterval applies the default and the floor. Callers that expose the
// interval as configuration pass what they were given through this.
func NormaliseInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return DefaultInterval
	}
	if interval < MinInterval {
		return MinInterval
	}
	return interval
}

// Subscribe points key at cfg.Host, creating the shared entry if it is new. A
// key already subscribed is moved, so a reload supersedes rather than
// duplicates. ctx bounds the refresh goroutine.
//
// Nothing is resolved here — an inline lookup would put DNS on whatever path
// loads a subscriber — but a name already resolved delivers its state at once.
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

	// Attached before the subscription it supersedes is released, so a reload
	// of a name's only subscriber keeps the entry rather than rebuilding an
	// empty one — which would discard the last known good set and the stale
	// TTL protecting it, worst when an outage is what prompted the reload.
	if previous, ok := s.subs[key]; ok {
		delete(s.subs, key)
		s.detachLocked(previous)
	}

	s.subs[key] = sub
	s.recomputeLocked(e)

	// Read under the lock, delivered off it.
	current := e.published.Load()

	s.ensureRunningLocked(ctx)
	s.mu.Unlock()

	// Without this a subscriber joining an already-resolved name would compute
	// its first membership change against an empty set, so a departed address
	// would not register as departed and its resources never be retired.
	if current != nil && sub.onChange != nil {
		sub.onChange(current)
	}

	return sub, nil
}

// ReleaseKey drops whatever subscription key holds, for subscribers that are
// reconciled rather than torn down.
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

// Refresh resolves every registered name now, on the calling goroutine.
func (s *Scheduler) Refresh(ctx context.Context) {
	s.mu.Lock()
	all := make([]*entry, 0, len(s.entries))
	for _, e := range s.entries {
		all = append(all, e)
	}
	s.mu.Unlock()

	s.refreshAll(ctx, all)
}

// Lookups is the number of lookups completed since the scheduler started.
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

	// Applied to an injected resolver too, so a stub that hangs cannot wedge
	// the cycle it is part of.
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

// release drops sub, unless it has already been superseded under its key.
func (s *Scheduler) release(sub *Subscription) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if current, ok := s.subs[sub.key]; !ok || current != sub {
		return
	}
	delete(s.subs, sub.key)
	s.detachLocked(sub)
}

// detachLocked removes sub, dropping the entry when nothing else wants it.
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

// recomputeLocked derives an entry's interval and stale TTL from its
// subscribers. The shortest of each wins, since one refresh serves them all.
func (s *Scheduler) recomputeLocked(e *entry) {
	// Shortest interval wins: one refresh serves everyone, and only the
	// shortest satisfies them all.
	//
	// Stale TTL goes the other way. Reaching it discards the addresses for
	// every subscriber, so the longest wins and a zero — never give up —
	// decides the entry outright.
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
	// A goroutine whose context is done may not have cleared `running` yet;
	// waking it would leave the entries with nothing refreshing them. A nil
	// runCtx means the loop was suppressed deliberately, as tests do.
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

// run is the single refresh goroutine. It takes its own wake channel, so a
// replaced goroutine cannot clear the flag its replacement set.
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

// refreshAll resolves a set of names, maxConcurrentLookups at a time.
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

// nextWait is how long to sleep before the earliest refresh falls due.
//
// Computed after the refresh pass: an entry just refreshed holds the nearest
// deadline, so taking the minimum beforehand would let the longest interval in
// the map decide how often the shortest one runs.
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

// dueEntries returns the entries whose next refresh has arrived.
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

// refresh resolves one name and publishes what it established.
//
// A successful answer, with records or without, is applied as it stands, as is
// an authoritative NXDOMAIN: all three are facts about the name. A resolver
// that could not be reached is not, so the addresses are kept and the entry
// backs off, bounded by the stale TTL.
func (s *Scheduler) refresh(ctx context.Context, e *entry) {
	// One resolution of a name at a time: concurrent refreshes publish out of
	// order, leaving a subscriber tracking a set that was already superseded.
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

		// Nothing published yet, so there is no stale set to bound.
		case e.published.Load() == nil:
			published, notify = s.publishLocked(e, nil, Unreachable)

		case e.staleTTL > 0 && !e.lastSuccess.IsZero() &&
			s.timeNow().Sub(e.lastSuccess) > e.staleTTL:
			published, notify = s.publishLocked(e, nil, Unreachable)
		}
	}

	s.mu.Unlock()

	// Off the lock, so a slow subscriber cannot delay every other name.
	for _, onChange := range notify {
		onChange(published)
	}
}

// publishLocked swaps in a new state unless it matches the current one, and
// returns the callbacks owed a notification.
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

// backoffLocked doubles the interval on consecutive failures, up to MaxBackoff.
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

// isNameNotFound distinguishes an authoritative NXDOMAIN from no answer.
func isNameNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
