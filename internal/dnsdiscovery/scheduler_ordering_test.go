package dnsdiscovery

import (
	"context"
	"fmt"
	"math/rand/v2"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func orderingScheduler() *Scheduler {
	return &Scheduler{
		entries: map[string]*entry{},
		subs:    map[string]*Subscription{},
		running: true, // no background loop
		wake:    make(chan struct{}, 1),
		Jitter:  func(d time.Duration) time.Duration { return d },
	}
}

// Subscribe reads the published set under the lock and delivers it after
// releasing, so a concurrent refresh can overtake it. No subscriber may ever
// see a version go backwards.
func TestSubscribeNeverDeliversAStaleState(t *testing.T) {
	s := orderingScheduler()

	var round atomic.Int64
	s.Lookup = func(context.Context, string) ([]string, error) {
		// A different set every call, so every refresh publishes.
		return []string{fmt.Sprintf("10.0.0.%d", round.Add(1)%250+1)}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if _, err := s.Subscribe(ctx, "anchor", Config{Host: "svc", Interval: time.Hour}); err != nil {
		t.Fatal(err)
	}

	// Hammer refreshes while subscriptions are created against the same name.
	var refreshers sync.WaitGroup
	for i := 0; i < 4; i++ {
		refreshers.Add(1)
		go func() {
			defer refreshers.Done()
			for ctx.Err() == nil {
				s.Refresh(ctx)
			}
		}()
	}

	var failures atomic.Int64
	var subscribers sync.WaitGroup
	for i := 0; i < 64; i++ {
		subscribers.Add(1)
		go func(i int) {
			defer subscribers.Done()

			var last uint64
			onChange := func(st *State) {
				if st.Version <= last {
					failures.Add(1)
					t.Errorf("subscriber %d saw version %d after %d", i, st.Version, last)
				}
				last = st.Version
			}

			sub, err := s.Subscribe(ctx, fmt.Sprintf("api-%d", i), Config{
				Host: "svc", Interval: time.Hour, OnChange: onChange,
			})
			if err != nil {
				t.Error(err)
				return
			}
			time.Sleep(2 * time.Millisecond)
			sub.Release()
		}(i)
	}

	subscribers.Wait()
	cancel()
	refreshers.Wait()

	if failures.Load() != 0 {
		t.Fatalf("%d out-of-order deliveries", failures.Load())
	}
}

// deliver must drop a state the subscriber has already been handed a newer
// version of, whichever order the two calls arrive in.
func TestDeliverDropsSupersededStates(t *testing.T) {
	var got []uint64
	sub := &Subscription{onChange: func(st *State) { got = append(got, st.Version) }}

	sub.deliver(&State{Version: 2, Addrs: []string{"a"}})
	sub.deliver(&State{Version: 1, Addrs: []string{"b"}}) // stale, dropped
	sub.deliver(&State{Version: 2, Addrs: []string{"c"}}) // duplicate, dropped
	sub.deliver(&State{Version: 3, Addrs: []string{"d"}})

	want := []uint64{2, 3}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("delivered %v, want %v", got, want)
	}
}

// The cached aggregates must agree with a full rescan after any sequence of
// arrivals and departures.
func TestEntryAggregatesMatchFullRescan(t *testing.T) {
	intervals := []time.Duration{5 * time.Second, 30 * time.Second, time.Minute}
	staleTTLs := []time.Duration{0, time.Minute, 5 * time.Minute}

	ctx := context.Background()
	s := orderingScheduler()

	live := map[string]bool{}
	rng := rand.New(rand.NewPCG(1, 2))

	for step := 0; step < 3000; step++ {
		key := fmt.Sprintf("api-%d", rng.IntN(25))

		if live[key] && rng.IntN(3) == 0 {
			s.ReleaseKey(key)
			delete(live, key)
		} else {
			if _, err := s.Subscribe(ctx, key, Config{
				Host:     "svc",
				Interval: intervals[rng.IntN(len(intervals))],
				StaleTTL: staleTTLs[rng.IntN(len(staleTTLs))],
			}); err != nil {
				t.Fatal(err)
			}
			live[key] = true
		}

		s.mu.Lock()
		if e, ok := s.entries["svc"]; ok {
			incremental := aggregatesOf(e)
			s.recomputeLocked(e)
			rescan := aggregatesOf(e)

			// Restore the incremental state, or the check would heal any
			// drift it just found and later steps would start from correct.
			applyAggregates(e, incremental)

			if incremental != rescan {
				s.mu.Unlock()
				t.Fatalf("step %d: cached aggregates disagree with a full rescan:\n incremental %+v\n rescan      %+v",
					step, incremental, rescan)
			}
		}
		s.mu.Unlock()
	}
}

// entryState is the comparable part of an entry: everything addSubLocked and
// removeSubLocked maintain without rescanning.
type entryState struct {
	aggregates
	StaleTTL time.Duration
}

func aggregatesOf(e *entry) entryState {
	return entryState{e.aggregates, e.staleTTL}
}

func applyAggregates(e *entry, a entryState) {
	e.aggregates, e.staleTTL = a.aggregates, a.StaleTTL
}

func TestLookupConcurrency(t *testing.T) {
	cases := map[int]int{
		0:     minConcurrentLookups,
		8:     minConcurrentLookups,
		48:    minConcurrentLookups,
		200:   34,
		1000:  167,
		10000: maxConcurrentLookups,
	}

	for due, want := range cases {
		if got := lookupConcurrency(due); got != want {
			t.Errorf("lookupConcurrency(%d) = %d, want %d", due, got, want)
		}
	}

	// A batch of timing-out names has to clear inside one refresh interval.
	for _, due := range []int{200, 1000} {
		limit := lookupConcurrency(due)
		cycle := time.Duration((due+limit-1)/limit) * LookupTimeout
		if cycle > DefaultInterval {
			t.Errorf("%d names at %v each take %v with %d workers, over the %v interval",
				due, LookupTimeout, cycle, limit, DefaultInterval)
		}
	}
}

// A name already being refreshed must not consume a worker slot.
func TestRefreshSkipsAnEntryInFlight(t *testing.T) {
	s := orderingScheduler()

	release := make(chan struct{})
	var calls atomic.Int64
	s.Lookup = func(context.Context, string) ([]string, error) {
		if calls.Add(1) == 1 {
			<-release
		}
		return []string{"10.0.0.1"}, nil
	}

	ctx := context.Background()
	sub, err := s.Subscribe(ctx, "api", Config{Host: "svc", Interval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.refresh(ctx, sub.entry)
	}()

	// Wait for the first lookup to be in flight, then race a second at it.
	for calls.Load() == 0 {
		runtime.Gosched()
	}
	s.refresh(ctx, sub.entry)

	if got := calls.Load(); got != 1 {
		t.Fatalf("a busy entry was refreshed again: %d lookups, want 1", got)
	}

	close(release)
	wg.Wait()
}
