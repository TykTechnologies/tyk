package cache

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultLRUMaxEntries       = 5000
	DefaultEvictionLogInterval = 5 * time.Minute
)

// LogFunc receives rate-limited eviction-summary log lines. Compatible
// with logrus's Warnf signature.
type LogFunc func(format string, args ...any)

// LRUOptions tunes a process-wide LRU cache wired from gateway config.
// Zero-valued fields fall back to package defaults so callers can pass a
// zero struct safely.
type LRUOptions struct {
	Log        LogFunc
	TTL        time.Duration
	MaxEntries int
	Unbounded  bool
	Enabled    bool
}

// ResolveMaxEntries returns the effective LRU capacity for opts.
func ResolveMaxEntries(opts LRUOptions) int {
	if opts.Unbounded {
		return 0
	}

	if opts.MaxEntries <= 0 {
		return DefaultLRUMaxEntries
	}

	return opts.MaxEntries
}

// EvictionLogger aggregates per-bucket eviction counts and emits one
// summary log line per tick. Safe for concurrent use. Bucket name "" is
// treated as the single-counter case (the summary line omits the breakdown).
type EvictionLogger struct {
	log    LogFunc
	ticker atomic.Pointer[time.Ticker]
	done   chan struct{}
	prefix string
	counts sync.Map
	once   sync.Once
}

// NewEvictionLogger returns a logger that emits "<prefix>: evicted..."
// lines. prefix is the human label for the cache family.
func NewEvictionLogger(prefix string, log LogFunc) *EvictionLogger {
	return &EvictionLogger{prefix: prefix, log: log, done: make(chan struct{})}
}

// Record increments the counter for the given bucket. Pass "" if the
// logger only owns one counter.
func (e *EvictionLogger) Record(bucket string) {
	v, ok := e.counts.Load(bucket)
	if !ok {
		v, _ = e.counts.LoadOrStore(bucket, new(atomic.Int64))
	}

	counter, ok := v.(*atomic.Int64)
	if !ok {
		return
	}
	counter.Add(1)
}

// Tick drains counters and emits a single log line if any are non-zero.
// Exposed so tests can drive the ticker deterministically.
func (e *EvictionLogger) Tick() {
	if e.log == nil {
		return
	}
	type pair struct {
		k string
		n int64
	}

	var pairs []pair
	e.counts.Range(func(k, v any) bool {
		counter, ok := v.(*atomic.Int64)
		if !ok {
			return true
		}
		key, ok := k.(string)
		if !ok {
			return true
		}
		n := counter.Swap(0)
		if n > 0 {
			pairs = append(pairs, pair{key, n})
		}
		return true
	})

	if len(pairs) == 0 {
		return
	}

	if len(pairs) == 1 && pairs[0].k == "" {
		e.log("%s: evicted %d entries in last interval", e.prefix, pairs[0].n)
		return
	}
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, fmt.Sprintf("cache=%s n=%d", p.k, p.n))
	}

	e.log("%s: evicted entries in last interval — %s", e.prefix, strings.Join(parts, ", "))
}

// Start spawns the ticker goroutine. Safe to call once per logger.
func (e *EvictionLogger) Start(interval time.Duration) {
	t := time.NewTicker(interval)
	e.ticker.Store(t)
	go func() {
		for {
			select {
			case <-e.done:
				return
			case <-t.C:
				e.Tick()
			}
		}
	}()
}

// Stop halts the ticker and unblocks the goroutine started by Start.
// Idempotent.
func (e *EvictionLogger) Stop() {
	e.once.Do(func() {
		if t := e.ticker.Swap(nil); t != nil {
			t.Stop()
		}

		close(e.done)
	})
}
