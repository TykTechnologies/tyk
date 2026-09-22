package dnsdiscovery

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
)

const (
	DefaultInterval = 30 * time.Second
	MinInterval     = 5 * time.Second

	// DefaultStaleTTL is applied by callers; zero here means unlimited.
	DefaultStaleTTL = 300 * time.Second

	// StaleTTLUnlimited keeps the last good set while the resolver is down.
	StaleTTLUnlimited = time.Duration(0)

	LookupTimeout = 5 * time.Second
	MaxBackoff    = 5 * time.Minute

	// RefreshJitterFraction is one-sided, keeping the interval above MinInterval.
	RefreshJitterFraction = 0.1

	// BackoffJitterFraction is symmetric, to break up gateways failing in step.
	BackoffJitterFraction = 0.5

	idleWait = time.Minute
	minWait  = 10 * time.Millisecond

	minConcurrentLookups = 8
	maxConcurrentLookups = 256

	// EmptyAnswerThreshold is how many consecutive empty or NXDOMAIN answers
	// drop the address set. One is often a resolver blip.
	EmptyAnswerThreshold = 2
)

// lookupConcurrency sizes a batch so names that time out still clear within one
// refresh interval: DefaultInterval/LookupTimeout batches fit in an interval.
func lookupConcurrency(due int) int {
	batches := int(DefaultInterval / LookupTimeout)
	limit := (due + batches - 1) / batches
	if limit < minConcurrentLookups {
		return minConcurrentLookups
	}
	if limit > maxConcurrentLookups {
		return maxConcurrentLookups
	}
	return limit
}

// LookupFunc resolves a host to a set of addresses.
type LookupFunc func(ctx context.Context, host string) ([]string, error)

// Config is what one subscriber asks for.
type Config struct {
	// Host is the DNS name to resolve, without a port.
	Host string

	// Interval of zero means DefaultInterval; see NormaliseInterval.
	Interval time.Duration

	// StaleTTL bounds the last known good set.
	StaleTTL time.Duration

	// OnChange runs unlocked, must not block, and never goes backwards.
	OnChange func(*State)
}

// Scheduler refreshes names in the background, one entry per distinct name.
// The zero value is ready to use.
type Scheduler struct {
	mu sync.Mutex

	entries map[string]*entry
	subs    map[string]*Subscription

	version uint64
	running bool
	wake    chan struct{}

	// The running loop's cancellation signal. Nil where no loop was started,
	// or where its context cannot be cancelled.
	runDone <-chan struct{}

	// Set before the first Subscribe; the refresh goroutine reads them.
	Lookup LookupFunc
	Now    func() time.Time
	Jitter func(time.Duration) time.Duration

	lookups atomic.Int64
}

// aggregates folds the subscribers of one name into the values refresh reads:
// shortest interval, since one refresh serves everyone, and longest stale TTL,
// since it discards addresses for everyone. The counters say how many sit at
// the current extreme, so a departure only rescans when the last one leaves.
type aggregates struct {
	interval      time.Duration
	maxStaleTTL   time.Duration
	atMinInterval int
	atMaxStale    int
	unboundedRefs int
}

func (a *aggregates) fold(sub *Subscription) {
	switch {
	case a.interval == 0 || sub.interval < a.interval:
		a.interval, a.atMinInterval = sub.interval, 1
	case sub.interval == a.interval:
		a.atMinInterval++
	}

	switch {
	case sub.staleTTL <= 0:
		a.unboundedRefs++
	case a.maxStaleTTL == 0 || sub.staleTTL > a.maxStaleTTL:
		a.maxStaleTTL, a.atMaxStale = sub.staleTTL, 1
	case sub.staleTTL == a.maxStaleTTL:
		a.atMaxStale++
	}
}

// entry is shared by every subscriber on one name. All fields except
// published are guarded by Scheduler.mu.
type entry struct {
	host string

	// Taken before Scheduler.mu.
	refreshMu sync.Mutex

	published atomic.Pointer[State]

	aggregates
	staleTTL     time.Duration
	nextDue      time.Time
	failures     int
	emptyAnswers int
	lastSuccess  time.Time
	subs         map[*Subscription]struct{}
}

// Subscription is one subscriber's handle on a name.
type Subscription struct {
	key      string
	host     string
	interval time.Duration
	staleTTL time.Duration
	onChange func(*State)

	// Set once, so a superseded subscription goes on reporting its last set.
	entry *entry
	sched *Scheduler

	detached bool

	// Subscribe delivers after releasing Scheduler.mu, so a refresh can
	// overtake it. These keep the subscriber's view monotonic.
	notifyMu    sync.Mutex
	lastVersion uint64
}

// State returns the published address set, or nil before the first
// resolution. It is never mutated.
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

// Release drops this subscription, and the entry with it when nothing else
// wants that name. An already superseded subscription is ignored.
func (s *Subscription) Release() {
	if s == nil || s.sched == nil {
		return
	}
	s.sched.release(s)
}

// deliver drops any state older than one already delivered.
func (s *Subscription) deliver(state *State) {
	if s == nil || s.onChange == nil || state == nil {
		return
	}

	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()

	if state.Version <= s.lastVersion {
		return
	}
	s.lastVersion = state.Version

	s.onChange(state)
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

// Subscribe points key at cfg.Host, superseding any existing subscription for
// that key. Nothing is resolved here.
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
	s.addSubLocked(e, sub)

	// Attached before the one it supersedes is released, so a reload of a
	// name's only subscriber keeps the entry.
	if previous, ok := s.subs[key]; ok {
		delete(s.subs, key)
		s.detachLocked(previous)
	}

	s.subs[key] = sub

	current := e.published.Load()

	s.ensureRunningLocked(ctx)
	s.mu.Unlock()

	sub.deliver(current)

	return sub, nil
}

// ReleaseKey drops the subscription registered under key.
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

	ctx, cancel := context.WithTimeout(ctx, LookupTimeout)
	defer cancel()

	if s.Lookup != nil {
		return s.Lookup(ctx, host)
	}

	return net.DefaultResolver.LookupHost(ctx, host)
}

// nextRefresh spreads successful cycles upward only.
func (s *Scheduler) nextRefresh(base time.Duration) time.Duration {
	if s.Jitter != nil {
		return s.Jitter(base)
	}
	span := int64(float64(base) * RefreshJitterFraction)
	if base <= 0 || span <= 0 {
		return base
	}
	return base + time.Duration(rand.Int64N(span))
}

// nextBackoff doubles from base, spreads the result, and clamps to MinInterval.
func (s *Scheduler) nextBackoff(base time.Duration, failures int) time.Duration {
	interval := base
	for i := 1; i < failures && interval < MaxBackoff; i++ {
		interval *= 2
	}
	if interval > MaxBackoff {
		interval = MaxBackoff
	}

	if s.Jitter != nil {
		return s.Jitter(interval)
	}

	span := int64(float64(interval) * BackoffJitterFraction)
	if span > 0 {
		interval = interval - time.Duration(span) + time.Duration(rand.Int64N(2*span))
	}
	if interval < MinInterval {
		interval = MinInterval
	}
	return interval
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
	s.removeSubLocked(e, sub)
}

// addSubLocked folds one arrival into the aggregates in constant time.
func (s *Scheduler) addSubLocked(e *entry, sub *Subscription) {
	previous := e.interval
	e.fold(sub)
	e.applyStaleTTL()
	s.pullNextDueLocked(e, previous)
}

// removeSubLocked is constant time unless the departing subscriber held an
// extreme alone.
func (s *Scheduler) removeSubLocked(e *entry, sub *Subscription) {
	rescan := false

	if sub.interval == e.interval {
		e.atMinInterval--
		rescan = e.atMinInterval <= 0
	}

	if sub.staleTTL <= 0 {
		e.unboundedRefs--
	} else if sub.staleTTL == e.maxStaleTTL {
		e.atMaxStale--
		rescan = rescan || e.atMaxStale <= 0
	}

	if rescan {
		s.recomputeLocked(e)
		return
	}

	e.applyStaleTTL()
}

// recomputeLocked rebuilds the aggregates in O(subscribers).
func (s *Scheduler) recomputeLocked(e *entry) {
	previous := e.interval

	e.aggregates = aggregates{}
	for sub := range e.subs {
		e.fold(sub)
	}

	e.applyStaleTTL()
	s.pullNextDueLocked(e, previous)
}

// applyStaleTTL resolves the aggregate into the value refresh reads.
func (e *entry) applyStaleTTL() {
	if e.unboundedRefs > 0 {
		e.staleTTL = StaleTTLUnlimited
		return
	}
	e.staleTTL = e.maxStaleTTL
}

// pullNextDueLocked brings the next refresh forward when a new subscriber
// shortened the entry's interval.
func (s *Scheduler) pullNextDueLocked(e *entry, previous time.Duration) {
	if previous == 0 || e.interval == 0 || e.interval >= previous {
		return
	}

	if due := s.timeNow().Add(e.interval); due.Before(e.nextDue) {
		e.nextDue = due
	}
}

func (s *Scheduler) ensureRunningLocked(ctx context.Context) {
	// A goroutine whose context is done may not have cleared running yet, and
	// waking it would leave the entries with nothing refreshing them.
	if s.running && !signalled(s.runDone) {
		select {
		case s.wake <- struct{}{}:
		default:
		}
		return
	}

	s.running = true
	s.runDone = ctx.Done()
	s.wake = make(chan struct{}, 1)
	go s.run(ctx, s.wake)
}

// signalled reports whether done has fired. A nil channel never does.
func signalled(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// run takes its own wake channel, so a replaced goroutine cannot clear the
// flag its replacement set.
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
	if len(due) == 0 {
		return
	}
	if len(due) == 1 {
		s.refresh(ctx, due[0])
		return
	}

	group := new(errgroup.Group)
	group.SetLimit(lookupConcurrency(len(due)))
	for _, e := range due {
		group.Go(func() error {
			s.refresh(ctx, e)
			return nil
		})
	}
	_ = group.Wait()
}

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

// refresh resolves one name and publishes the result.
func (s *Scheduler) refresh(ctx context.Context, e *entry) {
	// Skipped rather than queued, or a name already in flight holds a slot
	// while the cycle that owns it finishes.
	if !e.refreshMu.TryLock() {
		return
	}

	addrs, err := s.resolve(ctx, e.host)
	addrs = Normalise(addrs)

	s.mu.Lock()
	base := e.interval
	if base <= 0 {
		base = DefaultInterval
	}

	var published *State
	var notify []*Subscription
	if err == nil {
		published, notify = s.applyAnswerLocked(e, base, addrs)
	} else {
		published, notify = s.applyFailureLocked(e, base, err)
	}
	s.mu.Unlock()

	// Released before the callbacks, so a slow subscriber cannot hold up the
	// next lookup.
	e.refreshMu.Unlock()

	for _, sub := range notify {
		sub.deliver(published)
	}
}

// applyAnswerLocked takes a successful lookup as it stands.
func (s *Scheduler) applyAnswerLocked(e *entry, base time.Duration, addrs []string) (*State, []*Subscription) {
	e.failures = 0
	e.lastSuccess = s.timeNow()
	e.nextDue = e.lastSuccess.Add(s.nextRefresh(base))

	if len(addrs) > 0 {
		e.emptyAnswers = 0
		return s.publishLocked(e, addrs, Resolved)
	}

	if e.confirmEmpty() {
		return s.publishLocked(e, nil, Empty)
	}
	return nil, nil
}

// applyFailureLocked backs off. An authoritative NXDOMAIN is applied as it
// stands; anything else keeps the addresses until the stale TTL runs out.
func (s *Scheduler) applyFailureLocked(e *entry, base time.Duration, err error) (*State, []*Subscription) {
	now := s.timeNow()
	e.failures++
	e.nextDue = now.Add(s.nextBackoff(base, e.failures))

	switch {
	case isNameNotFound(err):
		if e.confirmEmpty() {
			return s.publishLocked(e, nil, NotFound)
		}

	// Nothing published yet, so no stale set to bound.
	case e.published.Load() == nil:
		return s.publishLocked(e, nil, Unreachable)

	case e.staleTTL > 0 && !e.lastSuccess.IsZero() && now.Sub(e.lastSuccess) > e.staleTTL:
		return s.publishLocked(e, nil, Unreachable)
	}
	return nil, nil
}

// confirmEmpty reports whether an empty answer should be published. Nothing
// published yet means there is no address set worth protecting.
func (e *entry) confirmEmpty() bool {
	if e.emptyAnswers < EmptyAnswerThreshold {
		e.emptyAnswers++
	}
	return e.emptyAnswers >= EmptyAnswerThreshold || e.published.Load() == nil
}

func (s *Scheduler) publishLocked(e *entry, addrs []string, outcome Outcome) (*State, []*Subscription) {
	if current := e.published.Load(); current != nil &&
		current.Outcome == outcome && equalAddrs(current.Addrs, addrs) {
		return nil, nil
	}

	s.version++
	state := &State{Version: s.version, Addrs: addrs, Outcome: outcome}
	e.published.Store(state)

	notify := make([]*Subscription, 0, len(e.subs))
	for sub := range e.subs {
		if sub.onChange != nil {
			notify = append(notify, sub)
		}
	}
	return state, notify
}

func isNameNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
