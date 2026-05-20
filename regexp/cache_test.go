package regexp

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCache_SetGet(t *testing.T) {
	c := newCache(time.Minute, true)

	c.add("key", "value")

	got, ok := c.getString("key")
	if !ok {
		t.Fatal("expected cache hit, got miss")
	}
	if got != "value" {
		t.Fatalf("expected 'value', got %q", got)
	}
}

func TestCache_Purge(t *testing.T) {
	c := newCache(time.Minute, true)

	c.add("key1", "value1")
	c.add("key2", "value2")

	c.reset(true)

	if _, ok := c.getString("key1"); ok {
		t.Error("expected cache miss after purge, got hit for key1")
	}
	if _, ok := c.getString("key2"); ok {
		t.Error("expected cache miss after purge, got hit for key2")
	}
}

// T1
func TestCache_EvictsAtCap(t *testing.T) {
	c := newCacheWithSize(0, 5, true, "", nil)

	for i := 0; i < 6; i++ {
		c.add(fmt.Sprintf("key-%d", i), fmt.Sprintf("val-%d", i))
	}

	if got := c.lru.Len(); got != 5 {
		t.Fatalf("expected Len=5 after 6 adds, got %d", got)
	}
	if _, ok := c.getString("key-0"); ok {
		t.Error("expected key-0 to be evicted")
	}
	if _, ok := c.getString("key-5"); !ok {
		t.Error("expected key-5 to still be present")
	}
}

// T2
func TestCache_TTLEviction(t *testing.T) {
	c := newCacheWithSize(100*time.Millisecond, 100, true, "", nil)

	c.add("k", "v")

	time.Sleep(200 * time.Millisecond)

	if got := c.lru.Len(); got != 0 {
		t.Fatalf("expected entry to expire (Len=0), got Len=%d", got)
	}
}

// T3
func TestCache_NoTTL(t *testing.T) {
	c := newCacheWithSize(0, 100, true, "", nil)

	c.add("k", "v")

	time.Sleep(200 * time.Millisecond)

	if _, ok := c.getString("k"); !ok {
		t.Fatal("expected k to still be present (ttl=0)")
	}
}

// T4 — Configure must apply both knobs to the live package caches:
// the MaxEntries cap enforces eviction at 100, and the TTL drives
// time-based expiry.
func TestConfigure_AppliesOpts(t *testing.T) {
	t.Cleanup(func() {
		applyCacheConfig(CacheOptions{Enabled: true})
	})

	t.Run("size_cap_enforced", func(t *testing.T) {
		applyCacheConfig(CacheOptions{
			TTL:        30 * time.Second,
			MaxEntries: 100,
			Enabled:    true,
		})

		for i := 0; i < 101; i++ {
			if _, err := Compile(fmt.Sprintf("^t4-size-%d-.*$", i)); err != nil {
				t.Fatalf("Compile #%d failed: %v", i, err)
			}
		}

		if got := CompileCacheLen(); got != 100 {
			t.Fatalf("expected compileCache.Len=100, got %d", got)
		}
	})

	t.Run("ttl_enforced", func(t *testing.T) {
		applyCacheConfig(CacheOptions{
			TTL:        100 * time.Millisecond,
			MaxEntries: 100,
			Enabled:    true,
		})

		if _, err := Compile("^t4-ttl-victim.*$"); err != nil {
			t.Fatalf("Compile failed: %v", err)
		}
		if got := CompileCacheLen(); got != 1 {
			t.Fatalf("expected Len=1 immediately after Compile, got %d", got)
		}

		time.Sleep(200 * time.Millisecond)

		if got := CompileCacheLen(); got != 0 {
			t.Fatalf("expected entry to expire after TTL, got Len=%d", got)
		}
	})
}

// T8b — evictionLogger drains counters and emits one log line per tick.
func TestEvictionLogger(t *testing.T) {
	var logged []string
	rep := newEvictionLogger(func(format string, args ...interface{}) {
		logged = append(logged, fmt.Sprintf(format, args...))
	})

	rep.record("compile")
	rep.record("compile")
	rep.record("match")
	rep.tick()

	if got := len(logged); got != 1 {
		t.Fatalf("expected exactly 1 log line, got %d", got)
	}
	if !contains(logged[0], "cache=compile n=2") || !contains(logged[0], "cache=match n=1") {
		t.Errorf("log line missing expected counts; got: %s", logged[0])
	}

	logged = nil
	rep.tick()
	if len(logged) != 0 {
		t.Errorf("expected no log when no evictions in window; got: %v", logged)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestCache_RaceSameKey(t *testing.T) {
	Reset(true)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			rx, err := Compile("^abc.*$")
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if !rx.MatchString("abcxyz") {
				t.Error("regexp did not match expected input")
			}
		}()
	}

	wg.Wait()
}

// TestCache_ConcurrentReads_SharedRegex covers the safety claim that backs
// the removal of cache.getRegexp's defensive re.Copy(): Go 1.12+ supports
// concurrent reads on *regexp.Regexp, so the cache returning the same
// pointer to many goroutines must be race-free across every read method
// exposed by the wrapper. Run under -race.
func TestCache_ConcurrentReads_SharedRegex(t *testing.T) {
	Reset(true)

	methods := []func(*Regexp){
		func(r *Regexp) { _ = r.MatchString("abc123def") },
		func(r *Regexp) { _ = r.Match([]byte("abc123def")) },
		func(r *Regexp) { _ = r.ReplaceAllString("abc123def", "X") },
		func(r *Regexp) { _ = r.ReplaceAllLiteralString("abc123def", "X") },
		func(r *Regexp) { _ = r.ReplaceAllStringFunc("abc123def", strings.ToUpper) },
		func(r *Regexp) { _ = r.FindString("abc123def") },
		func(r *Regexp) { _ = r.FindStringIndex("abc123def") },
		func(r *Regexp) { _ = r.FindStringSubmatch("abc123def") },
		func(r *Regexp) { _ = r.FindAllString("abc123abc456", -1) },
		func(r *Regexp) { _ = r.FindAllStringSubmatch("abc123abc456", -1) },
		func(r *Regexp) { _ = r.NumSubexp() },
		func(r *Regexp) { _ = r.SubexpNames() },
		func(r *Regexp) { _, _ = r.LiteralPrefix() },
		func(r *Regexp) { _ = r.String() },
	}

	const goroutines = 200
	const iterations = 200
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				r, err := Compile("^abc.*$")
				if err != nil {
					t.Errorf("goroutine %d: compile error: %v", i, err)
					return
				}
				methods[(i+j)%len(methods)](r)
			}
		}()
	}
	wg.Wait()
}

// TestCache_ConcurrentResetAndReads verifies Reset()'s atomic.Bool toggle
// (cache.isEnabled) plus lru.Purge() do not race with concurrent
// enabled()/Compile() calls on the hot path. Run under -race.
func TestCache_ConcurrentResetAndReads(t *testing.T) {
	Reset(true)

	const readers = 50
	const resets = 5
	var wg sync.WaitGroup
	wg.Add(readers + resets)

	stop := make(chan struct{})

	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = Compile("^reset-race.*$")
				_, _ = MatchString("^reset-race.*$", "reset-race-input")
			}
		}()
	}

	for i := 0; i < resets; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				Reset(true)
				time.Sleep(time.Microsecond)
			}
		}()
	}

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestCache_ConcurrentConfigureAndReads exercises the atomic.Pointer swap
// in applyCacheConfig against concurrent hot-path Load()s. The new cache
// instance must take over cleanly without tearing reads on the old one.
// Run under -race.
func TestCache_ConcurrentConfigureAndReads(t *testing.T) {
	applyCacheConfig(CacheOptions{Enabled: true})

	const readers = 50
	var wg sync.WaitGroup
	wg.Add(readers + 1)

	stop := make(chan struct{})

	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = Compile("^cfg-race.*$")
				_, _ = MatchString("^cfg-race.*$", "cfg-race-input")
			}
		}()
	}

	go func() {
		defer wg.Done()
		for j := 0; j < 5; j++ {
			applyCacheConfig(CacheOptions{
				MaxEntries: 100 + j*200,
				Enabled:    true,
			})
			time.Sleep(5 * time.Millisecond)
		}
	}()

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestCache_RaceDistinctKeys(t *testing.T) {
	const n = 50
	c := newCache(time.Minute, true)

	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			key := fmt.Sprintf("pattern-%d", i)
			c.add(key, fmt.Sprintf("value-%d", i))
			c.getString(key)
		}()
	}

	wg.Wait()
}
