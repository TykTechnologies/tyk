package dnsdiscovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type stubResolver struct {
	mu      sync.Mutex
	answers map[string][]string
	errs    map[string]error
	calls   map[string]int
}

func newStubResolver() *stubResolver {
	return &stubResolver{
		answers: map[string][]string{},
		errs:    map[string]error{},
		calls:   map[string]int{},
	}
}

func (r *stubResolver) set(host string, addrs ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answers[host] = addrs
	delete(r.errs, host)
}

func (r *stubResolver) fail(host string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs[host] = err
}

func (r *stubResolver) failNotFound(host string) {
	r.fail(host, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true})
}

func (r *stubResolver) callsFor(host string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[host]
}

func (r *stubResolver) lookup(_ context.Context, host string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.calls[host]++
	if err, ok := r.errs[host]; ok {
		return nil, err
	}
	return r.answers[host], nil
}

func storeMax(v *atomic.Int64, n int64) {
	for old := v.Load(); n > old; old = v.Load() {
		if v.CompareAndSwap(old, n) {
			return
		}
	}
}

func newTestScheduler(resolver *stubResolver) *Scheduler {
	s := &Scheduler{}
	configureTestScheduler(s, resolver)
	s.running = true
	return s
}

func configureTestScheduler(s *Scheduler, resolver *stubResolver) {
	s.entries = map[string]*entry{}
	s.subs = map[string]*Subscription{}
	s.wake = make(chan struct{}, 1)
	s.Lookup = resolver.lookup
	s.Jitter = func(d time.Duration) time.Duration { return d }
}

func subscribe(t *testing.T, s *Scheduler, key, host string, interval time.Duration) *Subscription {
	t.Helper()

	return subscribeWith(t, s, key, host, Config{Interval: interval})
}

func subscribeWith(t *testing.T, s *Scheduler, key, host string, cfg Config) *Subscription {
	t.Helper()

	cfg.Host = host
	sub, err := s.Subscribe(context.Background(), key, cfg)
	if err != nil {
		t.Fatalf("subscribe %s to %s: %v", key, host, err)
	}
	return sub
}

func subscribeAndRefresh(t *testing.T, s *Scheduler, key, host string, cfg Config) *Subscription {
	t.Helper()

	sub := subscribeWith(t, s, key, host, cfg)
	s.refresh(context.Background(), sub.entry)
	return sub
}

func (s *Scheduler) refreshAndReportDelay(ctx context.Context, e *entry) time.Duration {
	before := time.Now()
	s.refresh(ctx, e)

	s.mu.Lock()
	defer s.mu.Unlock()
	return e.nextDue.Sub(before)
}

func TestScheduler_OneLookupPerHostname(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc-a", "10.0.0.1", "10.0.0.2")
	resolver.set("svc-b", "10.0.1.1")

	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	for i := 0; i < 8; i++ {
		subscribe(t, scheduler, fmt.Sprintf("api-a-%d", i), "svc-a", 30*time.Second)
	}
	for i := 0; i < 2; i++ {
		subscribe(t, scheduler, fmt.Sprintf("api-b-%d", i), "svc-b", 30*time.Second)
	}

	scheduler.refreshAll(ctx, scheduler.dueEntries())

	if got := resolver.callsFor("svc-a"); got != 1 {
		t.Errorf("svc-a was resolved %d times for 8 subscribers, want 1", got)
	}
	if got := resolver.callsFor("svc-b"); got != 1 {
		t.Errorf("svc-b was resolved %d times for 2 subscribers, want 1", got)
	}

	for _, e := range scheduler.entries {
		scheduler.refresh(ctx, e)
	}
	if got := resolver.callsFor("svc-a"); got != 2 {
		t.Errorf("svc-a was resolved %d times after two cycles, want 2", got)
	}

	if len(scheduler.entries) != 2 {
		t.Errorf("scheduler holds %d entries for 10 subscribers on 2 hostnames, want 2", len(scheduler.entries))
	}
}

func TestScheduler_ReleaseDropsEntryWhenLastSubscriberLeaves(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")

	scheduler := newTestScheduler(resolver)

	first := subscribe(t, scheduler, "api-1", "svc", 30*time.Second)
	second := subscribe(t, scheduler, "api-2", "svc", 30*time.Second)

	first.Release()
	if len(scheduler.entries) != 1 {
		t.Fatal("entry dropped while api-2 still wants it")
	}

	second.Release()
	if len(scheduler.entries) != 0 {
		t.Fatalf("entry survived the last subscriber leaving: %d entries", len(scheduler.entries))
	}

	second.Release()
	scheduler.ReleaseKey("api-2")
}

func TestScheduler_ReleaseIsIgnoredOnceSuperseded(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")

	scheduler := newTestScheduler(resolver)

	superseded := subscribe(t, scheduler, "api-1", "svc", 30*time.Second)
	current := subscribe(t, scheduler, "api-1", "svc", 30*time.Second)

	superseded.Release()

	if len(scheduler.entries) != 1 {
		t.Fatal("releasing a superseded subscription dropped the one that replaced it")
	}
	if scheduler.subs["api-1"] != current {
		t.Fatal("the current subscription was replaced by the release of an older one")
	}
}

func TestScheduler_RepointingASubscriberMovesItsSubscription(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("old", "10.0.0.1")
	resolver.set("new", "10.0.1.1")

	scheduler := newTestScheduler(resolver)

	subscribe(t, scheduler, "api-1", "old", 30*time.Second)
	subscribe(t, scheduler, "api-1", "new", 30*time.Second)

	if _, ok := scheduler.entries["old"]; ok {
		t.Error("the previous hostname is still being refreshed after the subscriber was repointed")
	}
	e, ok := scheduler.entries["new"]
	if !ok {
		t.Fatal("the new hostname was not subscribed")
	}
	if len(e.subs) != 1 {
		t.Errorf("new entry has %d subscribers, want 1", len(e.subs))
	}
}

func TestScheduler_SharedHostnameTakesShortestInterval(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")

	scheduler := newTestScheduler(resolver)

	slow := subscribe(t, scheduler, "api-slow", "svc", 60*time.Second)
	subscribe(t, scheduler, "api-fast", "svc", 5*time.Second)

	if got := scheduler.entries["svc"].interval; got != 5*time.Second {
		t.Errorf("shared entry refreshes every %s, want the shortest requested 5s", got)
	}

	scheduler.ReleaseKey("api-fast")
	if got := scheduler.entries["svc"].interval; got != 60*time.Second {
		t.Errorf("entry still refreshes every %s after the eager subscriber left, want 60s", got)
	}

	slow.Release()
}

func TestScheduler_RepointingRecomputesTheNameItLeft(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("shared", "10.0.0.1")
	resolver.set("elsewhere", "10.0.1.1")

	scheduler := newTestScheduler(resolver)

	subscribe(t, scheduler, "api-slow", "shared", time.Minute)
	subscribe(t, scheduler, "api-fast", "shared", 5*time.Second)

	subscribe(t, scheduler, "api-fast", "elsewhere", 5*time.Second)

	if got := scheduler.entries["shared"].interval; got != time.Minute {
		t.Errorf("shared still refreshes every %s after its eager subscriber left, want 1m", got)
	}
}

func TestScheduler_FailedLookupKeepsLastGoodAndBacksOff(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1", "10.0.0.2")

	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	sub := subscribeAndRefresh(t, scheduler, "api-1", "svc", Config{Interval: 10 * time.Second})
	before := sub.State()
	if !before.Usable() || len(before.Addrs) != 2 {
		t.Fatalf("first resolution did not publish two addresses: %+v", before)
	}

	resolver.fail("svc", errors.New("servfail"))

	firstBackoff := scheduler.refreshAndReportDelay(ctx, sub.entry)
	after := sub.State()
	if !after.Usable() || len(after.Addrs) != 2 {
		t.Fatalf("a failed lookup discarded the last good set: %+v", after)
	}
	if !after.Failing {
		t.Error("a failed lookup did not mark the snapshot failing")
	}
	if after.Version == before.Version {
		t.Error("the first failure did not publish a new version")
	}
	if !after.Confirmed.Equal(before.Confirmed) {
		t.Error("a failed lookup moved the confirmation time")
	}

	secondBackoff := scheduler.refreshAndReportDelay(ctx, sub.entry)
	if secondBackoff <= firstBackoff {
		t.Errorf("consecutive failures did not back off: %s then %s", firstBackoff, secondBackoff)
	}
	if got := sub.State(); got.Version != after.Version {
		t.Error("a second consecutive failure published another version")
	}

	resolver.set("svc", "10.0.0.1", "10.0.0.2", "10.0.0.3")
	scheduler.refresh(ctx, sub.entry)
	if sub.entry.failures != 0 {
		t.Errorf("failure count is %d after a successful lookup, want 0", sub.entry.failures)
	}
	if got := sub.State(); !got.Usable() || len(got.Addrs) != 3 || got.Failing {
		t.Fatalf("recovery did not publish the new set: %+v", got)
	}
}

func TestScheduler_EmptyAnswerIsPublishedAsSuch(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1", "10.0.0.2")

	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	sub := subscribeAndRefresh(t, scheduler, "api-1", "svc", Config{Interval: 10 * time.Second})

	resolver.set("svc")

	scheduler.refresh(ctx, sub.entry)
	if got := sub.State(); !got.Usable() {
		t.Fatal("one empty answer dropped the address set")
	}

	scheduler.refresh(ctx, sub.entry)

	got := sub.State()
	if got == nil {
		t.Fatal("nothing published after an empty answer")
	}
	if got.Usable() {
		t.Fatalf("published %v after an empty answer, want no addresses", got.Addrs)
	}
	if got.Outcome != Empty {
		t.Fatalf("outcome is %s after an empty answer, want %s", got.Outcome, Empty)
	}
}

func TestScheduler_SingleEmptyAnswerIsIgnored(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1", "10.0.0.2")

	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	sub := subscribeAndRefresh(t, scheduler, "api-1", "svc", Config{Interval: 10 * time.Second})
	first := sub.State()

	resolver.set("svc")
	scheduler.refresh(ctx, sub.entry)

	resolver.set("svc", "10.0.0.1", "10.0.0.2")
	scheduler.refresh(ctx, sub.entry)

	got := sub.State()
	if !got.Usable() || len(got.Addrs) != 2 {
		t.Fatalf("a single empty answer disturbed the set: %+v", got)
	}
	if got.Version != first.Version {
		t.Fatalf("republished across a blip: version %d, want %d", got.Version, first.Version)
	}
}

func TestScheduler_FirstAnswerEmptyIsPublishedAtOnce(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc")

	scheduler := newTestScheduler(resolver)
	sub := subscribeAndRefresh(t, scheduler, "api-1", "svc", Config{Interval: 10 * time.Second})

	got := sub.State()
	if got == nil || got.Outcome != Empty {
		t.Fatalf("first answer empty published %+v, want %s", got, Empty)
	}
}

func TestScheduler_UnchangedAnswerDoesNotBumpVersion(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.2", "10.0.0.1")

	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	sub := subscribeAndRefresh(t, scheduler, "api-1", "svc", Config{Interval: 10 * time.Second})
	first := sub.State()

	resolver.set("svc", "10.0.0.1", "10.0.0.2")
	scheduler.refresh(ctx, sub.entry)

	second := sub.State()
	if second.Version != first.Version {
		t.Errorf("a reordered but unchanged answer bumped the version from %d to %d",
			first.Version, second.Version)
	}
	if second.Addrs[0] != "10.0.0.1" {
		t.Errorf("published set is not sorted: %v", second.Addrs)
	}
}

func TestScheduler_OnChangeFiresOnMembershipChangesOnly(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")

	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	var mu sync.Mutex
	var seen [][]string
	record := func(state *State) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, state.Addrs)
	}

	sub := subscribeAndRefresh(t, scheduler, "api-1", "svc", Config{
		Interval: 10 * time.Second,
		OnChange: record,
	})

	resolver.set("svc", "10.0.0.1")
	scheduler.refresh(ctx, sub.entry)

	resolver.set("svc", "10.0.0.2")
	scheduler.refresh(ctx, sub.entry)

	mu.Lock()
	defer mu.Unlock()

	if len(seen) != 2 {
		t.Fatalf("OnChange fired %d times for one first answer and one change, want 2: %v", len(seen), seen)
	}
	if seen[0][0] != "10.0.0.1" || seen[1][0] != "10.0.0.2" {
		t.Fatalf("OnChange saw %v, want the first set then the changed one", seen)
	}
}

func TestScheduler_DiscoversWithoutTraffic(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")

	scheduler := newTestScheduler(resolver)
	scheduler.running = false

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sub, err := scheduler.Subscribe(ctx, "api-1", Config{Host: "svc", Interval: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	resolver.set("svc", "10.0.0.1", "10.0.0.2")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if state := sub.State(); state.Usable() && len(state.Addrs) == 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("the scheduler did not pick up the second address without any traffic; published %+v", sub.State())
}

func TestScheduler_ShortIntervalIsNotStarvedByLongOne(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("fast", "10.0.0.1")
	resolver.set("slow", "10.0.1.1")

	scheduler := newTestScheduler(resolver)
	scheduler.running = false

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if _, err := scheduler.Subscribe(ctx, "api-slow", Config{Host: "slow", Interval: time.Hour}); err != nil {
		t.Fatalf("subscribe slow: %v", err)
	}
	if _, err := scheduler.Subscribe(ctx, "api-fast", Config{Host: "fast", Interval: 20 * time.Millisecond}); err != nil {
		t.Fatalf("subscribe fast: %v", err)
	}

	before := resolver.callsFor("fast")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if resolver.callsFor("fast") >= before+3 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("the 20ms hostname was refreshed %d times in 5s (want at least %d); "+
		"an hour-long interval on an unrelated hostname is deciding how often it runs",
		resolver.callsFor("fast")-before, 3)
}

func TestScheduler_SubscribeDoesNotResolveInline(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")

	scheduler := newTestScheduler(resolver)
	sub := subscribe(t, scheduler, "api-1", "svc", time.Minute)

	if got := resolver.callsFor("svc"); got != 0 {
		t.Errorf("Subscribe performed %d lookups; the scheduler goroutine owns the first one", got)
	}
	if sub.State() != nil {
		t.Error("Subscribe published an address set, so it must have resolved inline")
	}

	if len(scheduler.dueEntries()) != 1 {
		t.Error("a newly subscribed hostname is not due, so the loop would wait an interval before resolving it")
	}
}

func TestScheduler_NameNotFoundIsConfirmedByASecondAnswer(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1", "10.0.0.2")

	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	sub := subscribeAndRefresh(t, scheduler, "api-1", "svc", Config{Interval: 10 * time.Second})

	if got := sub.State(); !got.Usable() || len(got.Addrs) != 2 {
		t.Fatalf("first resolution published %+v, want two addresses", got)
	}

	resolver.failNotFound("svc")

	scheduler.refresh(ctx, sub.entry)
	if got := sub.State(); !got.Usable() {
		t.Fatal("one NXDOMAIN dropped the address set")
	}

	scheduler.refresh(ctx, sub.entry)

	got := sub.State()
	if got.Usable() {
		t.Fatalf("published %v after the name stopped existing, want no addresses", got.Addrs)
	}
	if got.Outcome != NotFound {
		t.Fatalf("outcome is %s after an authoritative NXDOMAIN, want %s", got.Outcome, NotFound)
	}
}

func TestScheduler_UnchangedAnswerAdvancesConfirmation(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")
	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	scheduler.Now = func() time.Time { return now }

	sub := subscribeAndRefresh(t, scheduler, "api-1", "svc", Config{Interval: 10 * time.Second})
	first := sub.State()

	now = now.Add(10 * time.Second)
	scheduler.refresh(ctx, sub.entry)

	second := sub.State()
	if second.Version != first.Version {
		t.Fatalf("an unchanged answer bumped the version from %d to %d", first.Version, second.Version)
	}
	if !second.Confirmed.Equal(now) {
		t.Fatalf("confirmation time is %s after an unchanged answer at %s", second.Confirmed, now)
	}
}

func TestScheduler_UnchangedAnswerKeepsItsVersionWhileAnotherHostnameChanges(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc-a", "10.0.0.1")
	resolver.set("svc-b", "10.0.1.1")
	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	a := subscribeAndRefresh(t, scheduler, "api-a", "svc-a", Config{Interval: 10 * time.Second})
	first := a.State().Version

	b := subscribeAndRefresh(t, scheduler, "api-b", "svc-b", Config{Interval: 10 * time.Second})
	resolver.set("svc-b", "10.0.1.2")
	scheduler.refresh(ctx, b.entry)

	scheduler.refresh(ctx, a.entry)
	if got := a.State().Version; got != first {
		t.Fatalf("svc-a answered the same set and its version moved from %d to %d because svc-b changed", first, got)
	}
}

func TestScheduler_RecoveryPublishesANewVersionWithUnchangedAddresses(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")
	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	var versions []uint64
	sub := subscribeAndRefresh(t, scheduler, "api-1", "svc", Config{
		Interval: 10 * time.Second,
		OnChange: func(state *State) { versions = append(versions, state.Version) },
	})

	resolver.fail("svc", errors.New("i/o timeout"))
	scheduler.refresh(ctx, sub.entry)
	failing := sub.State()

	resolver.set("svc", "10.0.0.1")
	scheduler.refresh(ctx, sub.entry)
	recovered := sub.State()

	if !failing.Failing || recovered.Failing {
		t.Fatalf("failure state did not follow the lookups: %+v then %+v", failing, recovered)
	}
	if recovered.Version <= failing.Version {
		t.Fatalf("recovery with unchanged addresses kept version %d", recovered.Version)
	}
	if len(versions) != 3 {
		t.Fatalf("subscriber saw %d versions, want the first answer, the failure and the recovery", len(versions))
	}
}

func TestState_Selectable(t *testing.T) {
	confirmed := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	clockReads := 0
	now := func() time.Time {
		clockReads++
		return confirmed.Add(2 * time.Minute)
	}
	stale := func() *State { return &State{Addrs: []string{"a"}, Confirmed: confirmed, Failing: true} }

	cases := []struct {
		name  string
		state *State
		ttl   time.Duration
		want  bool
		reads int
	}{
		{"nil", nil, time.Minute, false, 0},
		{"no addresses", &State{Outcome: Empty}, time.Minute, false, 0},
		{"healthy", &State{Addrs: []string{"a"}, Confirmed: confirmed}, time.Minute, true, 0},
		{"failing, unlimited", stale(), 0, true, 0},
		{"failing, inside the TTL", stale(), 5 * time.Minute, true, 1},
		{"failing, past the TTL", stale(), time.Minute, false, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clockReads = 0
			if got := tc.state.Selectable(tc.ttl, now); got != tc.want {
				t.Fatalf("Selectable = %v, want %v", got, tc.want)
			}
			if clockReads != tc.reads {
				t.Fatalf("read the clock %d times, want %d", clockReads, tc.reads)
			}
		})
	}
}

func TestScheduler_ReplacementRecomputesTheIntervalOnlyWhenItChanges(t *testing.T) {
	scheduler := newTestScheduler(newStubResolver())
	subscribe(t, scheduler, "api-1", "svc", 5*time.Second)
	subscribe(t, scheduler, "api-2", "svc", time.Minute)

	subscribe(t, scheduler, "api-1", "svc", 5*time.Second)
	if got := scheduler.entries["svc"].interval; got != 5*time.Second {
		t.Fatalf("a same-interval replacement moved the interval to %s", got)
	}

	subscribe(t, scheduler, "api-1", "svc", time.Hour)
	if got := scheduler.entries["svc"].interval; got != time.Minute {
		t.Fatalf("interval is %s after the 5s holder was replaced with an hour, want 1m", got)
	}
}

func TestScheduler_SubscribeRequiresAHost(t *testing.T) {
	scheduler := newTestScheduler(newStubResolver())

	if _, err := scheduler.Subscribe(context.Background(), "api-1", Config{}); !errors.Is(err, ErrNoHost) {
		t.Fatalf("Subscribe with no host returned %v, want %v", err, ErrNoHost)
	}
}

func TestNormaliseInterval(t *testing.T) {
	cases := map[time.Duration]time.Duration{
		0:                DefaultInterval,
		-time.Second:     DefaultInterval,
		time.Second:      MinInterval,
		4 * time.Second:  MinInterval,
		5 * time.Second:  5 * time.Second,
		60 * time.Second: 60 * time.Second,
	}

	for in, want := range cases {
		if got := NormaliseInterval(in); got != want {
			t.Errorf("NormaliseInterval(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestNormalise(t *testing.T) {
	got := Normalise([]string{"10.0.0.3", "", "10.0.0.1", "10.0.0.3", "10.0.0.2"})
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}

	if len(got) != len(want) {
		t.Fatalf("Normalise returned %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Normalise returned %v, want %v", got, want)
		}
	}

	if Normalise(nil) != nil {
		t.Error("Normalise(nil) allocated")
	}
}

func TestRemoved(t *testing.T) {
	cases := []struct {
		name      string
		was, now  []string
		wantCount int
		wantFirst string
	}{
		{"one left", []string{"a", "b"}, []string{"b"}, 1, "a"},
		{"all left", []string{"a", "b"}, nil, 2, "a"},
		{"nothing left", []string{"a", "b"}, []string{"a", "b", "c"}, 0, ""},
		{"nothing held", nil, []string{"a"}, 0, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Removed(tc.was, tc.now)
			if len(got) != tc.wantCount {
				t.Fatalf("Removed(%v, %v) = %v, want %d entries", tc.was, tc.now, got, tc.wantCount)
			}
			if tc.wantCount > 0 && got[0] != tc.wantFirst {
				t.Fatalf("Removed(%v, %v) = %v, want %s first", tc.was, tc.now, got, tc.wantFirst)
			}
		})
	}
}

func TestResolvable(t *testing.T) {
	cases := map[string]bool{
		"svc":                   true,
		"svc.default.svc":       true,
		"":                      false,
		"10.0.0.1":              false,
		"::1":                   false,
		"localhost":             false,
		"LOCALHOST":             false,
		"localhost.localdomain": true,
	}

	for host, want := range cases {
		if got := Resolvable(host); got != want {
			t.Errorf("Resolvable(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestScheduler_ReloadKeepsTheEntryAndItsState(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1", "10.0.0.2")

	scheduler := newTestScheduler(resolver)

	cfg := Config{Interval: 10 * time.Second}
	first := subscribeAndRefresh(t, scheduler, "api-1", "svc", cfg)
	if !first.State().Usable() {
		t.Fatal("no state after the first resolution")
	}

	before := resolver.callsFor("svc")
	second := subscribeWith(t, scheduler, "api-1", "svc", cfg)

	if got := resolver.callsFor("svc"); got != before {
		t.Errorf("a reload triggered %d extra lookups, want 0", got-before)
	}

	state := second.State()
	if !state.Usable() || len(state.Addrs) != 2 {
		t.Fatalf("the reloaded subscription reports %+v, want the two addresses the entry already held", state)
	}
	if got := len(scheduler.entries); got != 1 {
		t.Errorf("scheduler holds %d entries after a reload, want 1", got)
	}
}

func TestScheduler_ReloadDuringAnOutageKeepsTheSetAndItsAge(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1", "10.0.0.2")

	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	now := time.Now()
	scheduler.Now = func() time.Time { return now }

	cfg := Config{Interval: 10 * time.Second}
	sub := subscribeAndRefresh(t, scheduler, "api-1", "svc", cfg)
	confirmed := sub.State().Confirmed

	resolver.fail("svc", errors.New("i/o timeout"))
	now = now.Add(time.Minute)
	scheduler.refresh(ctx, sub.entry)
	if !sub.State().Usable() {
		t.Fatal("the stale set was dropped before any reload")
	}

	reloaded := subscribeWith(t, scheduler, "api-1", "svc", cfg)
	now = now.Add(time.Minute)
	scheduler.refresh(ctx, reloaded.entry)

	state := reloaded.State()
	if !state.Usable() {
		t.Fatalf("a reload two minutes into a one hour stale TTL withdrew the addresses: outcome=%s", state.Outcome)
	}
	if len(state.Addrs) != 2 {
		t.Fatalf("the reloaded subscription holds %v, want the two last known good addresses", state.Addrs)
	}
	if !state.Confirmed.Equal(confirmed) || !state.Failing {
		t.Fatalf("the reload reset the age of the addresses: %+v, confirmed at %s", state, confirmed)
	}
}

func TestScheduler_LateSubscriberReceivesTheCurrentSet(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1", "10.0.0.2", "10.0.0.3")

	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	subscribeAndRefresh(t, scheduler, "api-1", "svc", Config{Interval: 10 * time.Second})

	var mu sync.Mutex
	var seen [][]string
	late, err := scheduler.Subscribe(ctx, "api-2", Config{
		Host:     "svc",
		Interval: 10 * time.Second,
		OnChange: func(state *State) {
			mu.Lock()
			defer mu.Unlock()
			seen = append(seen, state.Addrs)
		},
	})
	if err != nil {
		t.Fatalf("subscribe api-2: %v", err)
	}

	mu.Lock()
	initial := len(seen)
	mu.Unlock()
	if initial != 1 {
		t.Fatalf("a late subscriber received %d callbacks on subscribe, want 1 carrying the current set", initial)
	}
	if got := late.State(); !got.Usable() || len(got.Addrs) != 3 {
		t.Fatalf("late subscriber reports %+v, want the three addresses already published", got)
	}

	resolver.set("svc", "10.0.0.1", "10.0.0.3")
	scheduler.refresh(ctx, late.entry)

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("late subscriber received %d callbacks, want 2", len(seen))
	}
	if gone := Removed(seen[0], seen[1]); len(gone) != 1 || gone[0] != "10.0.0.2" {
		t.Fatalf("the departed address computes as %v, want [10.0.0.2]", gone)
	}
}

func TestScheduler_StateIsSafeAcrossAReload(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1", "10.0.0.2")

	scheduler := newTestScheduler(resolver)
	sub := subscribeAndRefresh(t, scheduler, "api-1", "svc", Config{Interval: 10 * time.Second})

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if state := sub.State(); state != nil && !state.Usable() {
					t.Error("a superseded subscription reported an empty set while still serving")
					return
				}
			}
		}()
	}

	for i := 0; i < 50; i++ {
		subscribeWith(t, scheduler, "api-1", "svc", Config{Interval: 10 * time.Second})
	}

	close(stop)
	readers.Wait()
}

func TestScheduler_SupersededSubscriptionHearsNothingAfterItsReplacement(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc-a", "10.0.0.1")
	resolver.set("svc-b", "10.0.0.2")
	s := newTestScheduler(resolver)
	ctx := context.Background()

	var mu sync.Mutex
	var replaced, late bool

	reloader := func(*State) {
		mu.Lock()
		replaced = true
		mu.Unlock()
		if _, err := s.Subscribe(ctx, "api-1", Config{Host: "svc-b", OnChange: func(*State) {}}); err != nil {
			t.Error(err)
		}
	}
	superseded := func(*State) {
		mu.Lock()
		defer mu.Unlock()
		if replaced {
			late = true
		}
	}

	subscribeWith(t, s, "api-2", "svc-a", Config{OnChange: reloader})

	for attempt := 1; attempt <= 64; attempt++ {
		mu.Lock()
		replaced = false
		mu.Unlock()

		sub := subscribeWith(t, s, "api-1", "svc-a", Config{OnChange: superseded})
		resolver.set("svc-a", fmt.Sprintf("10.0.%d.1", attempt))
		s.refresh(ctx, sub.entry)

		mu.Lock()
		hit := late
		mu.Unlock()
		if hit {
			t.Fatalf("attempt %d: api-1's subscription on svc-a received a callback after api-1 had been repointed at svc-b", attempt)
		}
	}
}

func TestScheduler_FailureBeforeAnyAnswerIsUnresolved(t *testing.T) {
	resolver := newStubResolver()
	resolver.fail("svc", errors.New("i/o timeout"))
	s := newTestScheduler(resolver)

	sub := subscribeAndRefresh(t, s, "api-1", "svc", Config{Interval: 10 * time.Second})
	if got := sub.State(); got == nil || got.Outcome != Unresolved || !got.Failing {
		t.Fatalf("state after a failure with nothing resolved is %+v, want %s", got, Unresolved)
	}

	resolver.set("svc", "10.0.0.1")
	s.refresh(context.Background(), sub.entry)
	if got := sub.State(); !got.Usable() || got.Outcome != Resolved {
		t.Fatalf("state after the first answer is %+v, want %s", got, Resolved)
	}
}

func TestScheduler_AuthoritativeAbsenceKeepsTheRefreshInterval(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")
	s := newTestScheduler(resolver)

	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }

	const interval = 30 * time.Second
	sub := subscribeAndRefresh(t, s, "api-1", "svc", Config{Interval: interval})
	resolver.failNotFound("svc")

	for i := 0; i < 6; i++ {
		now = sub.entry.nextDue
		s.refresh(context.Background(), sub.entry)
	}
	if state := sub.State(); state.Usable() || state.Outcome != NotFound {
		t.Fatalf("state after six NXDOMAIN answers is %+v, want not found with no addresses", state)
	}

	resolver.set("svc", "10.0.0.2")
	if wait := s.nextWait(); wait > interval {
		t.Fatalf("a resolver answering NXDOMAIN is polled again in %s with refresh_interval %s; the service returning is noticed only then", wait, interval)
	}
}
