package dnsdiscovery

import (
	"context"
	"fmt"
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
		running: true,
		wake:    make(chan struct{}, 1),
		Jitter:  func(d time.Duration) time.Duration { return d },
	}
}

func TestSubscribeNeverDeliversAStaleState(t *testing.T) {
	s := orderingScheduler()

	var round atomic.Int64
	s.Lookup = func(context.Context, string) ([]string, error) {
		return []string{fmt.Sprintf("10.0.0.%d", round.Add(1)%250+1)}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if _, err := s.Subscribe(ctx, "anchor", Config{Host: "svc", Interval: time.Hour}); err != nil {
		t.Fatal(err)
	}

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

func TestDeliverDropsSupersededStates(t *testing.T) {
	var got []uint64
	sub := &Subscription{onChange: func(st *State) { got = append(got, st.Version) }}

	sub.deliver(&State{Version: 2, Addrs: []string{"a"}})
	sub.deliver(&State{Version: 1, Addrs: []string{"b"}})
	sub.deliver(&State{Version: 2, Addrs: []string{"c"}})
	sub.deliver(&State{Version: 3, Addrs: []string{"d"}})

	want := []uint64{2, 3}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("delivered %v, want %v", got, want)
	}
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

	for _, due := range []int{200, 1000} {
		limit := lookupConcurrency(due)
		cycle := time.Duration((due+limit-1)/limit) * LookupTimeout
		if cycle > DefaultInterval {
			t.Errorf("%d names at %v each take %v with %d workers, over the %v interval",
				due, LookupTimeout, cycle, limit, DefaultInterval)
		}
	}
}

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
