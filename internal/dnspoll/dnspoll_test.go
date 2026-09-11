package dnspoll

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

// scriptedLookup returns a LookupFunc that walks a script of results, repeating
// the last one once exhausted, and a func reporting how many lookups happened.
func scriptedLookup(script ...func() ([]string, error)) (LookupFunc, func() int) {
	var mu sync.Mutex
	calls := 0

	lookup := func(context.Context, string) ([]string, error) {
		mu.Lock()
		i := calls
		calls++
		mu.Unlock()

		if i >= len(script) {
			i = len(script) - 1
		}
		return script[i]()
	}

	return lookup, func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}
}

func ok(addrs ...string) func() ([]string, error) {
	return func() ([]string, error) { return addrs, nil }
}

func fails() func() ([]string, error) {
	return func() ([]string, error) { return nil, errors.New("SERVFAIL") }
}

// recorder collects the sets handed to OnChange.
type recorder struct {
	mu   sync.Mutex
	sets [][]string
}

func (r *recorder) onChange(addrs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sets = append(r.sets, addrs)
}

func (r *recorder) snapshot() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([][]string, len(r.sets))
	copy(out, r.sets)
	return out
}

// TestPollerHoldsLastGoodSet is the safety property the whole design rests on.
//
// grpc-go's balancer removes the children absent from an incoming address set
// before it decides whether to reject that set, so publishing an empty set —
// even briefly, even when DNS genuinely says the name has no addresses — tears
// down every healthy subconnection. On the plugin path every API carrying a
// plugin then returns 500; on the upstream path every request to the API fails.
//
// Both ways of reaching "no addresses" are covered, because they arrive through
// different code paths: a lookup that errors, and a lookup that succeeds with
// an empty answer. NXDOMAIN is the second kind, and it is the one grpc-go's own
// resolver gets wrong.
func TestPollerHoldsLastGoodSet(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failure func() ([]string, error)
	}{
		{"lookup error", fails()},
		{"empty but successful answer", ok()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookup, _ := scriptedLookup(ok("10.0.0.1", "10.0.0.2"), tc.failure)

			var rec recorder
			p, err := New(Config{
				Host:     "svc.test",
				Interval: 10 * time.Millisecond,
				Lookup:   lookup,
				OnChange: rec.onChange,
			})
			if err != nil {
				t.Fatal(err)
			}

			p.Start(context.Background())
			defer p.Stop()

			// Long enough for several failing polls after the good one.
			time.Sleep(100 * time.Millisecond)

			if got, want := p.Addresses(), []string{"10.0.0.1", "10.0.0.2"}; !reflect.DeepEqual(got, want) {
				t.Errorf("Addresses() = %v, want %v — the poller dropped its last known-good set "+
					"when lookups stopped working. Stale-but-working beats empty-and-correct.", got, want)
			}

			for i, set := range rec.snapshot() {
				if len(set) == 0 {
					t.Fatalf("OnChange call %d published an EMPTY address set. Consumers tear down "+
						"every healthy connection on one of these.", i)
				}
			}
		})
	}
}

// TestPollerOnChangeOnlyOnRealChange checks that a set which merely arrives in a
// different order is not reported as a membership change. CoreDNS shuffles its
// answers by default (the loadbalance plugin, in the standard kubeadm
// Corefile), so without this every poll would look like a scale event and
// rebuild the client's connections on a timer.
func TestPollerOnChangeOnlyOnRealChange(t *testing.T) {
	lookup, calls := scriptedLookup(
		ok("10.0.0.2", "10.0.0.1"),
		ok("10.0.0.1", "10.0.0.2"),             // same set, shuffled
		ok("10.0.0.1", "10.0.0.2", "10.0.0.1"), // same set, duplicated
		ok("10.0.0.1", "10.0.0.2", "10.0.0.3"), // a genuine scale-up
	)

	var rec recorder
	p, err := New(Config{
		Host:     "svc.test",
		Interval: 10 * time.Millisecond,
		Lookup:   lookup,
		OnChange: rec.onChange,
	})
	if err != nil {
		t.Fatal(err)
	}

	p.Start(context.Background())
	defer p.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for calls() < 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if calls() < 4 {
		t.Fatalf("only %d lookups in 2s, wanted at least 4", calls())
	}

	sets := rec.snapshot()
	want := [][]string{
		{"10.0.0.1", "10.0.0.2"},
		{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
	}
	if !reflect.DeepEqual(sets, want) {
		t.Errorf("OnChange saw %v, want %v — a reordered or duplicated answer must not count as a "+
			"membership change, and a genuine one must.", sets, want)
	}
}

// TestPollerBacksOffOnFailureOnly checks the direction of the backoff. Backing
// off after a failure protects CoreDNS during an outage; backing off because
// nothing changed would delay discovery of exactly the event this package
// exists to catch, so a steady-state poll must keep running at its interval.
func TestPollerBacksOffOnFailureOnly(t *testing.T) {
	const interval = 20 * time.Millisecond

	t.Run("no change does not slow polling", func(t *testing.T) {
		lookup, calls := scriptedLookup(ok("10.0.0.1"))

		p, _ := New(Config{Host: "svc.test", Interval: interval, Lookup: lookup})
		p.Start(context.Background())
		defer p.Stop()

		time.Sleep(10 * interval)

		// Allow generous slack for scheduling; the point is that polling did not
		// walk out to a long interval.
		if got := calls(); got < 5 {
			t.Errorf("only %d lookups in %v at a %v interval — polling backed off even though "+
				"every lookup succeeded, which would delay discovery of a scale-up",
				got, 10*interval, interval)
		}
	})

	t.Run("failure slows polling", func(t *testing.T) {
		lookup, calls := scriptedLookup(fails())

		p, _ := New(Config{Host: "svc.test", Interval: interval, Lookup: lookup})
		p.Start(context.Background())
		defer p.Stop()

		time.Sleep(10 * interval)

		// With doubling from the interval, 10 intervals of wall clock allows
		// roughly 1 (sync) + 3 ticks. Anything near the unthrottled count means
		// no backoff at all.
		if got := calls(); got > 6 {
			t.Errorf("%d lookups in %v of continuous failure — the poller is not backing off, so a "+
				"DNS outage would turn every gateway and API into sustained query pressure on "+
				"CoreDNS exactly when it can least absorb it", got, 10*interval)
		}
	})
}

// TestPollerStopWaits checks that Stop is synchronous. An API being unloaded
// must not leave a ticker running behind it, and a test that stops a poller
// must be able to rely on no further OnChange arriving.
func TestPollerStopWaits(t *testing.T) {
	lookup, _ := scriptedLookup(ok("10.0.0.1"), ok("10.0.0.2"))

	var mu sync.Mutex
	stopped := false
	afterStop := 0

	p, _ := New(Config{
		Host:     "svc.test",
		Interval: time.Millisecond,
		Lookup:   lookup,
		OnChange: func([]string) {
			mu.Lock()
			defer mu.Unlock()
			if stopped {
				afterStop++
			}
		},
	})

	p.Start(context.Background())
	time.Sleep(20 * time.Millisecond)

	p.Stop()
	mu.Lock()
	stopped = true
	mu.Unlock()

	time.Sleep(20 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if afterStop != 0 {
		t.Errorf("OnChange fired %d time(s) after Stop returned; Stop must wait for the poll "+
			"goroutine, or an unloaded API keeps a ticker alive", afterStop)
	}

	// Stopping twice, and stopping a poller that never started, must both be safe:
	// unload hooks are not guaranteed to run exactly once against a started poller.
	p.Stop()
	never, _ := New(Config{Host: "svc.test", Lookup: lookup})
	never.Stop()
}

// TestNewRequiresHost guards the one input that has no sensible default.
func TestNewRequiresHost(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("New accepted an empty Host; a poller with no name to resolve would silently do nothing")
	}
}
