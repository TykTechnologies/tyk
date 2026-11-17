package dnsdiscovery

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultInterval = 30 * time.Second
	MinInterval     = 5 * time.Second

	LookupTimeout = 5 * time.Second
	MaxBackoff    = 5 * time.Minute

	RefreshJitterFraction = 0.1
	BackoffJitterFraction = 0.5

	idleWait = time.Minute
	minWait  = 10 * time.Millisecond

	minConcurrentLookups = 8
	maxConcurrentLookups = 256

	EmptyAnswerThreshold = 2
)

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

type LookupFunc func(ctx context.Context, host string) ([]string, error)

type Config struct {
	Host     string
	Interval time.Duration
	OnChange func(*State)
}

type Scheduler struct {
	mu sync.Mutex

	entries map[string]*entry
	subs    map[string]*Subscription

	version uint64
	running bool
	wake    chan struct{}

	runDone <-chan struct{}

	Lookup LookupFunc
	Now    func() time.Time
	Jitter func(time.Duration) time.Duration

	lookups atomic.Int64

	slotsOnce sync.Once
	slots     chan struct{}
}

type entry struct {
	host      string
	published atomic.Pointer[State]

	interval     time.Duration
	nextDue      time.Time
	failures     int
	emptyAnswers int
	lastSuccess  time.Time
	confirmed    time.Time
	inFlight     bool
	subs         map[*Subscription]struct{}
}

type Subscription struct {
	key      string
	host     string
	interval time.Duration
	onChange func(*State)

	entry *entry
	sched *Scheduler

	detached bool

	notifyMu    sync.Mutex
	lastVersion uint64
	quiesced    bool
}

func (s *Subscription) State() *State {
	if s == nil || s.entry == nil {
		return nil
	}
	return s.entry.published.Load()
}

func (s *Subscription) Host() string {
	if s == nil {
		return ""
	}
	return s.host
}

func (s *Subscription) Release() {
	if s == nil || s.sched == nil {
		return
	}
	s.sched.release(s)
}

func (s *Subscription) deliver(state *State) {
	if s == nil || s.onChange == nil || state == nil {
		return
	}

	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()

	if s.quiesced || state.Version <= s.lastVersion {
		return
	}
	s.lastVersion = state.Version

	s.onChange(state)
}

func (s *Subscription) quiesce() {
	if s == nil {
		return
	}
	s.notifyMu.Lock()
	s.quiesced = true
	s.notifyMu.Unlock()
}

func NormaliseInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return DefaultInterval
	}
	if interval < MinInterval {
		return MinInterval
	}
	return interval
}

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
	s.attachLocked(e, sub)

	previous, superseded := s.subs[key]
	if superseded {
		delete(s.subs, key)
		unchanged := previous.entry == e && previous.interval == sub.interval
		s.detachLocked(previous, unchanged)
	}

	s.subs[key] = sub

	current := e.published.Load()

	s.ensureRunningLocked(ctx)
	s.mu.Unlock()

	if superseded {
		previous.quiesce()
	}
	sub.deliver(current)

	return sub, nil
}

func (s *Scheduler) ReleaseKey(key string) {
	s.mu.Lock()
	sub, ok := s.subs[key]
	if !ok {
		s.mu.Unlock()
		return
	}
	delete(s.subs, key)
	s.detachLocked(sub, false)
	s.mu.Unlock()

	sub.quiesce()
}

func (s *Scheduler) Refresh(ctx context.Context) {
	s.mu.Lock()
	all := make([]*entry, 0, len(s.entries))
	for _, e := range s.entries {
		all = append(all, e)
	}
	s.mu.Unlock()

	s.refreshAll(ctx, all)
}

func (s *Scheduler) Lookups() int64 {
	return s.lookups.Load()
}

func (s *Scheduler) timeNow() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Scheduler) lookupSlots() chan struct{} {
	s.slotsOnce.Do(func() { s.slots = make(chan struct{}, maxConcurrentLookups) })
	return s.slots
}

func (s *Scheduler) resolve(ctx context.Context, host string) ([]string, error) {
	slots := s.lookupSlots()
	select {
	case slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer s.releaseSlot()

	return s.lookupHoldingSlot(ctx, host)
}

func (s *Scheduler) lookupHoldingSlot(ctx context.Context, host string) ([]string, error) {
	s.lookups.Add(1)

	ctx, cancel := context.WithTimeout(ctx, LookupTimeout)
	defer cancel()

	if s.Lookup != nil {
		return s.Lookup(ctx, host)
	}

	return net.DefaultResolver.LookupHost(ctx, host)
}

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
	if current, ok := s.subs[sub.key]; !ok || current != sub {
		s.mu.Unlock()
		return
	}
	delete(s.subs, sub.key)
	s.detachLocked(sub, false)
	s.mu.Unlock()

	sub.quiesce()
}

func (s *Scheduler) detachLocked(sub *Subscription, minimumStands bool) {
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

	if minimumStands || sub.interval != e.interval {
		return
	}
	s.rescanIntervalLocked(e)
}

func (s *Scheduler) attachLocked(e *entry, sub *Subscription) {
	if e.interval != 0 && sub.interval >= e.interval {
		return
	}
	previous := e.interval
	e.interval = sub.interval
	s.pullNextDueLocked(e, previous)
}

func (s *Scheduler) rescanIntervalLocked(e *entry) {
	previous := e.interval
	e.interval = 0
	for sub := range e.subs {
		if e.interval == 0 || sub.interval < e.interval {
			e.interval = sub.interval
		}
	}
	s.pullNextDueLocked(e, previous)
}

func (s *Scheduler) pullNextDueLocked(e *entry, previous time.Duration) {
	if previous == 0 || e.interval == 0 || e.interval >= previous {
		return
	}

	if due := s.timeNow().Add(e.interval); due.Before(e.nextDue) {
		e.nextDue = due
	}
}

func (s *Scheduler) ensureRunningLocked(ctx context.Context) {
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

func signalled(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func (s *Scheduler) run(ctx context.Context, wake chan struct{}) {
	defer func() {
		s.mu.Lock()
		if s.wake == wake {
			s.running = false
		}
		s.mu.Unlock()
	}()

	var workers sync.WaitGroup
	defer workers.Wait()

	for {
		var timer <-chan time.Time
		if !s.launchDue(ctx, &workers) {
			timer = time.After(s.nextWait())
		}

		select {
		case <-ctx.Done():
			return
		case <-timer:
		case <-wake:
		}
	}
}

func (s *Scheduler) launchDue(ctx context.Context, workers *sync.WaitGroup) (saturated bool) {
	slots := s.lookupSlots()

	s.mu.Lock()
	now := s.timeNow()
	var due []*entry
	for _, e := range s.entries {
		if !e.inFlight && !e.nextDue.After(now) {
			due = append(due, e)
		}
	}
	sort.Slice(due, func(i, j int) bool { return due[i].nextDue.Before(due[j].nextDue) })

	launch := due[:0]
	for _, e := range due {
		select {
		case slots <- struct{}{}:
			e.inFlight = true
			launch = append(launch, e)
			continue
		default:
		}
		saturated = true
		break
	}
	s.mu.Unlock()

	for _, e := range launch {
		workers.Add(1)
		go func() {
			defer workers.Done()
			s.lookupInFlight(ctx, e)
		}()
	}
	return saturated
}

func (s *Scheduler) lookupInFlight(ctx context.Context, e *entry) {
	addrs, err := s.lookupHoldingSlot(ctx, e.host)
	s.releaseSlot()

	if ctx.Err() != nil {
		s.finish(e)
		return
	}
	s.apply(e, addrs, err)
}

func (s *Scheduler) refreshAll(ctx context.Context, due []*entry) {
	if len(due) == 1 {
		s.refresh(ctx, due[0])
		return
	}

	group := newBoundedGroup(lookupConcurrency(len(due)))
	for _, e := range due {
		group.Go(func() { s.refresh(ctx, e) })
	}
	group.Wait()
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
		if e.inFlight {
			continue
		}
		remaining := e.nextDue.Sub(now)
		if remaining < 0 {
			remaining = 0
		}
		if wait < 0 || remaining < wait {
			wait = remaining
		}
	}

	if wait < 0 {
		return idleWait
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

func (s *Scheduler) claim(e *entry) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if e.inFlight {
		return false
	}
	e.inFlight = true
	return true
}

func (s *Scheduler) finish(e *entry) {
	s.mu.Lock()
	e.inFlight = false
	s.mu.Unlock()
	s.signal()
}

func (s *Scheduler) signal() {
	s.mu.Lock()
	wake := s.wake
	s.mu.Unlock()

	select {
	case wake <- struct{}{}:
	default:
	}
}

func (s *Scheduler) releaseSlot() {
	<-s.lookupSlots()
	s.signal()
}

func (s *Scheduler) refresh(ctx context.Context, e *entry) {
	if !s.claim(e) {
		return
	}

	addrs, err := s.resolve(ctx, e.host)
	s.apply(e, addrs, err)
}

func (s *Scheduler) Warm(ctx context.Context) []string {
	s.mu.Lock()
	var cold []*entry
	for _, e := range s.entries {
		if e.published.Load() == nil {
			cold = append(cold, e)
		}
	}
	s.mu.Unlock()

	group := newBoundedGroup(lookupConcurrency(len(cold)))
	for _, e := range cold {
		if ctx.Err() != nil {
			break
		}
		group.Go(func() { s.warm(ctx, e) })
	}
	group.Wait()

	var unresolved []string
	for _, e := range cold {
		if e.published.Load() == nil {
			unresolved = append(unresolved, e.host)
		}
	}
	return unresolved
}

func (s *Scheduler) warm(ctx context.Context, e *entry) {
	for e.published.Load() == nil {
		if s.claim(e) {
			if e.published.Load() != nil {
				s.finish(e)
				return
			}

			addrs, err := s.resolve(ctx, e.host)
			if err != nil && ctx.Err() != nil {
				s.finish(e)
				return
			}
			s.apply(e, addrs, err)
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(minWait):
		}
	}
}

func (s *Scheduler) apply(e *entry, addrs []string, err error) {
	addrs = Normalise(addrs)

	s.mu.Lock()
	base := e.interval
	if base <= 0 {
		base = DefaultInterval
	}

	var published *State
	var notify []*Subscription
	switch {
	case err == nil:
		published, notify = s.applyAnswerLocked(e, base, addrs, Empty)
	case isNameNotFound(err):
		published, notify = s.applyAnswerLocked(e, base, nil, NotFound)
	default:
		published, notify = s.applyFailureLocked(e, base)
	}
	e.inFlight = false
	s.mu.Unlock()
	s.signal()

	for _, sub := range notify {
		sub.deliver(published)
	}
}

func (s *Scheduler) applyAnswerLocked(e *entry, base time.Duration, addrs []string, absent Outcome) (*State, []*Subscription) {
	e.failures = 0
	e.lastSuccess = s.timeNow()
	e.nextDue = e.lastSuccess.Add(s.nextRefresh(base))

	if len(addrs) > 0 {
		e.emptyAnswers = 0
		e.confirmed = e.lastSuccess
		return s.publishLocked(e, addrs, Resolved, false)
	}

	if e.confirmEmpty() {
		e.confirmed = e.lastSuccess
		return s.publishLocked(e, nil, absent, false)
	}

	current := e.published.Load()
	return s.publishLocked(e, current.Addrs, current.Outcome, current.Failing)
}

func (s *Scheduler) applyFailureLocked(e *entry, base time.Duration) (*State, []*Subscription) {
	e.failures++
	e.nextDue = s.timeNow().Add(s.nextBackoff(base, e.failures))

	current := e.published.Load()
	if current == nil {
		return s.publishLocked(e, nil, Unresolved, true)
	}
	return s.publishLocked(e, current.Addrs, current.Outcome, true)
}

func (e *entry) confirmEmpty() bool {
	if e.emptyAnswers < EmptyAnswerThreshold {
		e.emptyAnswers++
	}
	return e.emptyAnswers >= EmptyAnswerThreshold || !e.published.Load().Usable()
}

func (s *Scheduler) publishLocked(e *entry, addrs []string, outcome Outcome, failing bool) (*State, []*Subscription) {
	current := e.published.Load()
	changed := current == nil ||
		current.Outcome != outcome ||
		current.Failing != failing ||
		!equalAddrs(current.Addrs, addrs)

	var version uint64
	if changed {
		s.version++
		version = s.version
	} else {
		version = current.Version
	}

	state := &State{
		Version:   version,
		Addrs:     addrs,
		Outcome:   outcome,
		Confirmed: e.confirmed,
		Failing:   failing,
	}
	e.published.Store(state)

	if !changed {
		return nil, nil
	}

	notify := make([]*Subscription, 0, len(e.subs))
	for sub := range e.subs {
		if sub.onChange != nil {
			notify = append(notify, sub)
		}
	}
	return state, notify
}

type boundedGroup struct {
	wg    sync.WaitGroup
	slots chan struct{}
}

func newBoundedGroup(limit int) *boundedGroup {
	return &boundedGroup{slots: make(chan struct{}, limit)}
}

func (g *boundedGroup) Go(fn func()) {
	g.slots <- struct{}{}
	g.wg.Go(func() {
		defer func() { <-g.slots }()
		fn()
	})
}

func (g *boundedGroup) Wait() {
	g.wg.Wait()
}

func isNameNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
