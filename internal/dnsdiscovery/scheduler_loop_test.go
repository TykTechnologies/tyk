package dnsdiscovery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockingLookup struct {
	mu      sync.Mutex
	calls   map[string]int
	active  atomic.Int64
	peak    atomic.Int64
	release chan struct{}
}

func newBlockingLookup() *blockingLookup {
	return &blockingLookup{calls: map[string]int{}, release: make(chan struct{})}
}

func (b *blockingLookup) lookup(ctx context.Context, host string) ([]string, error) {
	b.mu.Lock()
	b.calls[host]++
	b.mu.Unlock()

	if !strings.HasPrefix(host, "slow") {
		return []string{"10.0.0.1"}, nil
	}

	n := b.active.Add(1)
	defer b.active.Add(-1)
	for old := b.peak.Load(); n > old && !b.peak.CompareAndSwap(old, n); old = b.peak.Load() {
	}

	select {
	case <-b.release:
		return []string{"10.0.9.1"}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (b *blockingLookup) callsFor(host string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls[host]
}

func loopScheduler(t *testing.T, lookup LookupFunc) (*Scheduler, context.CancelFunc) {
	t.Helper()

	s := orderingScheduler()
	s.Lookup = lookup
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.run(ctx, s.wake)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return s, cancel
}

func TestScheduler_SlowLookupsDoNotDelayAnotherName(t *testing.T) {
	blocking := newBlockingLookup()
	defer close(blocking.release)
	s, _ := loopScheduler(t, blocking.lookup)

	for i := 0; i < 49; i++ {
		if _, err := s.Subscribe(context.Background(), fmt.Sprintf("api-slow-%d", i), Config{Host: fmt.Sprintf("slow-%d", i), Interval: time.Hour}); err != nil {
			t.Fatal(err)
		}
	}
	waitUntil(t, time.Second, func() bool { return blocking.active.Load() == 49 })

	if _, err := s.Subscribe(context.Background(), "api-fast", Config{Host: "fast", Interval: 50 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}

	time.Sleep(600 * time.Millisecond)
	if got := blocking.callsFor("fast"); got < 5 {
		t.Fatalf("a 50ms name was looked up %d times in 600ms while 49 other lookups hung", got)
	}
	for i := 0; i < 49; i++ {
		if got := blocking.callsFor(fmt.Sprintf("slow-%d", i)); got != 1 {
			t.Fatalf("slow-%d was looked up %d times while its first lookup was still in flight", i, got)
		}
	}
}

func TestScheduler_SaturatedSlotsResumeWhenALookupFinishes(t *testing.T) {
	blocking := newBlockingLookup()
	s := orderingScheduler()
	s.slotsOnce.Do(func() { s.slots = make(chan struct{}, 2) })
	s.Lookup = blocking.lookup
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.run(ctx, s.wake)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	for i := 0; i < 3; i++ {
		if _, err := s.Subscribe(context.Background(), fmt.Sprintf("api-%d", i), Config{Host: fmt.Sprintf("slow-%d", i), Interval: time.Hour}); err != nil {
			t.Fatal(err)
		}
	}
	waitUntil(t, time.Second, func() bool { return blocking.active.Load() == 2 })

	time.Sleep(50 * time.Millisecond)
	if started := blocking.callsFor("slow-0") + blocking.callsFor("slow-1") + blocking.callsFor("slow-2"); started != 2 {
		t.Fatalf("%d lookups started with 2 slots", started)
	}

	blocking.release <- struct{}{}
	waitUntil(t, time.Second, func() bool {
		return blocking.callsFor("slow-0")+blocking.callsFor("slow-1")+blocking.callsFor("slow-2") == 3
	})
	if peak := blocking.peak.Load(); peak > 2 {
		t.Fatalf("%d lookups ran at once with 2 slots", peak)
	}
	close(blocking.release)
}

func TestScheduler_NextWaitIgnoresNamesInFlight(t *testing.T) {
	s := orderingScheduler()
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }

	sub, err := s.Subscribe(context.Background(), "api-1", Config{Host: "svc", Interval: time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	s.mu.Lock()
	sub.entry.nextDue = now.Add(-time.Second)
	sub.entry.inFlight = true
	s.mu.Unlock()

	if wait := s.nextWait(); wait != idleWait {
		t.Fatalf("an overdue name already being looked up set the wait to %s, which spins the loop", wait)
	}
}

func TestScheduler_CancelledLookupPublishesNothing(t *testing.T) {
	blocking := newBlockingLookup()
	s := orderingScheduler()
	s.Lookup = blocking.lookup
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.run(ctx, s.wake)
		close(done)
	}()

	sub, err := s.Subscribe(ctx, "api-1", Config{Host: "slow-0", Interval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, time.Second, func() bool { return blocking.active.Load() == 1 })

	cancel()
	<-done

	s.mu.Lock()
	inFlight := sub.entry.inFlight
	s.mu.Unlock()
	if inFlight {
		t.Fatal("the loop returned while its lookup was still running")
	}

	if state := sub.State(); state != nil {
		t.Fatalf("a lookup cancelled by shutdown published %+v", state)
	}
	s.mu.Lock()
	failures := sub.entry.failures
	s.mu.Unlock()
	if failures != 0 {
		t.Fatalf("a lookup cancelled by shutdown was recorded as %d failures", failures)
	}
}

func TestScheduler_UnconfirmedEmptyAnswerDoesNotReviveExpiredAddresses(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")
	s := newTestScheduler(resolver)
	ctx := context.Background()

	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	clock := func() time.Time { return now }
	const ttl = time.Minute

	sub := subscribeAndRefresh(t, s, "api-1", "svc", Config{Interval: 10 * time.Second})

	resolver.fail("svc", errors.New("i/o timeout"))
	now = now.Add(2 * ttl)
	s.refresh(ctx, sub.entry)
	if sub.State().Selectable(ttl, clock) {
		t.Fatal("addresses are selectable past the stale TTL")
	}

	resolver.failNotFound("svc")
	s.refresh(ctx, sub.entry)
	state := sub.State()
	if !state.Usable() {
		t.Fatal("one NXDOMAIN dropped the addresses before it was confirmed")
	}
	if state.Selectable(ttl, clock) {
		t.Fatalf("one unconfirmed NXDOMAIN made expired addresses selectable again: %+v", state)
	}

	s.refresh(ctx, sub.entry)
	if state := sub.State(); state.Usable() || state.Outcome != NotFound {
		t.Fatalf("a confirmed NXDOMAIN left %+v", state)
	}
}

func waitUntil(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestScheduler_LoopResumesWhenWarmUpFreesTheSlots(t *testing.T) {
	blocking := newBlockingLookup()
	s := orderingScheduler()
	s.slotsOnce.Do(func() { s.slots = make(chan struct{}, 2) })
	s.Lookup = blocking.lookup

	for i := 0; i < 2; i++ {
		if _, err := s.Subscribe(context.Background(), fmt.Sprintf("api-slow-%d", i), Config{Host: fmt.Sprintf("slow-%d", i), Interval: time.Hour}); err != nil {
			t.Fatal(err)
		}
	}

	warmed := make(chan struct{})
	go func() {
		s.Warm(context.Background())
		close(warmed)
	}()
	waitUntil(t, time.Second, func() bool { return blocking.active.Load() == 2 })

	if _, err := s.Subscribe(context.Background(), "api-fast", Config{Host: "fast", Interval: time.Hour}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.run(ctx, s.wake)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	time.Sleep(50 * time.Millisecond)
	if got := blocking.callsFor("fast"); got != 0 {
		t.Fatalf("fast was looked up %d times while warm-up held every slot", got)
	}

	close(blocking.release)
	<-warmed

	waitUntil(t, time.Second, func() bool { return blocking.callsFor("fast") == 1 })
}

func TestScheduler_RestartedLoopHearsAWorkerFromThePreviousRun(t *testing.T) {
	var calls atomic.Int64
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})

	s := &Scheduler{
		Jitter: func(d time.Duration) time.Duration { return d },
		Lookup: func(ctx context.Context, _ string) ([]string, error) {
			if calls.Add(1) == 1 {
				close(firstStarted)
				<-releaseFirst
				return nil, ctx.Err()
			}
			return []string{"10.0.0.1"}, nil
		},
	}

	first, cancelFirst := context.WithCancel(context.Background())
	sub, err := s.Subscribe(first, "api-1", Config{Host: "svc", Interval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	<-firstStarted

	cancelFirst()
	second, cancelSecond := context.WithCancel(context.Background())
	defer cancelSecond()
	if _, err := s.Subscribe(second, "api-2", Config{Host: "svc", Interval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	close(releaseFirst)

	waitUntil(t, time.Second, func() bool { return sub.State().Usable() })
}
