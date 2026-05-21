package cache

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestEvictionLogger_BucketedSummary covers the multi-bucket case: counters
// per bucket are drained and emitted as a single comma-separated line.
func TestEvictionLogger_BucketedSummary(t *testing.T) {
	var logged []string
	var mu sync.Mutex
	rep := NewEvictionLogger("regex cache", func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, fmt.Sprintf(format, args...))
	})

	rep.Record("compile")
	rep.Record("compile")
	rep.Record("match")
	rep.Tick()

	if got := len(logged); got != 1 {
		t.Fatalf("expected exactly 1 log line, got %d", got)
	}
	if !strings.Contains(logged[0], "cache=compile n=2") || !strings.Contains(logged[0], "cache=match n=1") {
		t.Errorf("log line missing expected counts; got: %s", logged[0])
	}
	if !strings.HasPrefix(logged[0], "regex cache: ") {
		t.Errorf("log line missing expected prefix; got: %s", logged[0])
	}

	logged = nil
	rep.Tick()
	if len(logged) != 0 {
		t.Errorf("expected no log when no evictions in window; got: %v", logged)
	}
}

// TestEvictionLogger_SingleCounter covers the case where the logger owns
// one counter (bucket=""): the summary line omits the cache=... breakdown.
func TestEvictionLogger_SingleCounter(t *testing.T) {
	var logged []string
	rep := NewEvictionLogger("path-regexp cache", func(format string, args ...any) {
		logged = append(logged, fmt.Sprintf(format, args...))
	})

	rep.Record("")
	rep.Record("")
	rep.Record("")
	rep.Tick()

	if got := len(logged); got != 1 {
		t.Fatalf("expected exactly 1 log line, got %d", got)
	}
	if logged[0] != "path-regexp cache: evicted 3 entries in last interval" {
		t.Errorf("unexpected log line: %q", logged[0])
	}
}

// TestEvictionLogger_NilLog drops Tick output when no LogFunc is wired.
func TestEvictionLogger_NilLog(_ *testing.T) {
	rep := NewEvictionLogger("x", nil)
	rep.Record("a")
	rep.Tick()
}

// TestEvictionLogger_StopUnblocksGoroutine verifies that Stop closes the
// done channel and the ticker goroutine exits — guarding against the
// `for range t.C` leak that motivated the redesign.
func TestEvictionLogger_StopUnblocksGoroutine(t *testing.T) {
	rep := NewEvictionLogger("x", func(string, ...any) {})

	var running atomic.Bool
	running.Store(true)
	done := make(chan struct{})

	// Wrap the goroutine via Start, then signal exit through Stop. We can't
	// observe the goroutine directly, but a hung Stop would block the test.
	rep.Start(10 * time.Millisecond)
	time.Sleep(30 * time.Millisecond)

	go func() {
		rep.Stop()
		running.Store(false)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop did not return within 1s — goroutine likely leaked")
	}
	if running.Load() {
		t.Fatal("Stop returned but running flag still true")
	}

	// Idempotent: a second Stop must not panic.
	rep.Stop()
}
