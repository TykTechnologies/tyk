package dnsdiscovery

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestScheduler_WarmResolvesUnpublishedNames(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc-a", "10.0.0.1")
	resolver.set("svc-b", "10.0.0.2", "10.0.0.3")
	s := newTestScheduler(resolver)

	a := subscribe(t, s, "api-a", "svc-a", time.Hour)
	b := subscribe(t, s, "api-b", "svc-b", time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if unresolved := s.Warm(ctx); len(unresolved) != 0 {
		t.Fatalf("names left unresolved: %v", unresolved)
	}
	if !a.State().Usable() || len(b.State().Addrs) != 2 {
		t.Fatalf("warm did not publish both names: %v %v", a.State(), b.State())
	}
}

func TestScheduler_WarmGivesUpAtTheDeadlineWithoutRecordingAFailure(t *testing.T) {
	resolver := newStubResolver()
	s := newTestScheduler(resolver)
	s.Lookup = func(ctx context.Context, _ string) ([]string, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	sub := subscribe(t, s, "api-a", "svc-a", time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	started := time.Now()
	unresolved := s.Warm(ctx)
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("warm took %s past a 50ms deadline", elapsed)
	}
	if len(unresolved) != 1 || unresolved[0] != "svc-a" {
		t.Fatalf("unresolved = %v, want [svc-a]", unresolved)
	}
	if sub.State() != nil {
		t.Fatalf("a lookup cut short by the deadline published %v", sub.State())
	}

	s.mu.Lock()
	failures := s.entries["svc-a"].failures
	s.mu.Unlock()
	if failures != 0 {
		t.Fatalf("recorded %d failures for a lookup cut short by the deadline", failures)
	}
}

func TestScheduler_WarmSkipsPublishedNames(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc-a", "10.0.0.1")
	s := newTestScheduler(resolver)

	subscribe(t, s, "api-a", "svc-a", time.Hour)
	s.Refresh(context.Background())
	before := resolver.callsFor("svc-a")

	s.Warm(context.Background())

	if after := resolver.callsFor("svc-a"); after != before {
		t.Fatalf("warm looked up an already published name %d more times", after-before)
	}
}

func TestScheduler_WarmBoundsConcurrentLookups(t *testing.T) {
	s := newTestScheduler(newStubResolver())

	const names = 1000
	var active, peak atomic.Int64
	release := make(chan struct{})
	s.Lookup = func(ctx context.Context, _ string) ([]string, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		select {
		case <-release:
			return []string{"10.0.0.1"}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	for i := range names {
		subscribe(t, s, fmt.Sprintf("api-%d", i), fmt.Sprintf("svc-%d", i), time.Hour)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		s.Warm(ctx)
		close(done)
	}()

	settled := time.Now().Add(500 * time.Millisecond)
	for active.Load() < names && time.Now().Before(settled) {
		time.Sleep(time.Millisecond)
	}
	close(release)
	<-done

	if limit := lookupConcurrency(names); peak.Load() > int64(limit) {
		t.Fatalf("warm ran %d lookups at once; the refresh loop bounds %d names to %d", peak.Load(), names, limit)
	}
}
