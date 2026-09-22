package dnsdiscovery

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// Refresh cost follows hostnames, not subscribers, which is what makes a
// background refresh affordable at gateway scale.

// No background goroutine: a benchmark measures only what it calls.
func benchScheduler(addrsPerHost int) *Scheduler {
	addrs := make([]string, 0, addrsPerHost)
	for i := 0; i < addrsPerHost; i++ {
		addrs = append(addrs, fmt.Sprintf("10.0.%d.%d", i/250, i%250+1))
	}

	return &Scheduler{
		entries: map[string]*entry{},
		subs:    map[string]*Subscription{},
		running: true, // no background loop during a benchmark
		wake:    make(chan struct{}, 1),
		Lookup: func(_ context.Context, _ string) ([]string, error) {
			return addrs, nil
		},
		Jitter: func(d time.Duration) time.Duration { return d },
	}
}

// Subscribers held at 1000 while hostnames vary, as a deployment has many
// APIs and few Services. Time should track hosts, flat in subscribers.
func BenchmarkRefreshCycle(b *testing.B) {
	const subscribers = 1000

	for _, hosts := range []int{1, 10, 100, 1000} {
		b.Run(fmt.Sprintf("subscribers=%d/hosts=%d", subscribers, hosts), func(b *testing.B) {
			scheduler := benchScheduler(4)
			ctx := context.Background()

			for i := 0; i < subscribers; i++ {
				host := fmt.Sprintf("svc-%d", i%hosts)
				if _, err := scheduler.Subscribe(ctx, fmt.Sprintf("api-%d", i), Config{Host: host, Interval: 30 * time.Second}); err != nil {
					b.Fatal(err)
				}
			}
			if got := len(scheduler.entries); got != hosts {
				b.Fatalf("scheduler holds %d entries, want %d", got, hosts)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				scheduler.Refresh(ctx)
			}
			b.StopTimer()

			// Hostnames, not subscribers.
			b.ReportMetric(float64(hosts), "lookups/cycle")
		})
	}
}

// Once per wake, growing with the number of distinct hostnames.
func BenchmarkDueEntries(b *testing.B) {
	for _, hosts := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("hosts=%d", hosts), func(b *testing.B) {
			scheduler := benchScheduler(4)
			ctx := context.Background()

			for i := 0; i < hosts; i++ {
				if _, err := scheduler.Subscribe(ctx, fmt.Sprintf("api-%d", i), Config{
					Host:     fmt.Sprintf("svc-%d", i),
					Interval: time.Hour,
				}); err != nil {
					b.Fatal(err)
				}
			}
			// Take them out of the due state, which they start in.
			scheduler.Refresh(ctx)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if due := scheduler.dueEntries(); len(due) != 0 {
					b.Fatalf("%d entries reported due with an hour-long interval", len(due))
				}
			}
		})
	}
}

// Every gateway reload runs Subscribe for every API.
func BenchmarkSubscribe(b *testing.B) {
	b.Run("new hostname", func(b *testing.B) {
		scheduler := benchScheduler(4)
		ctx := context.Background()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := scheduler.Subscribe(ctx, fmt.Sprintf("api-%d", i), Config{
				Host:     fmt.Sprintf("svc-%d", i),
				Interval: 30 * time.Second,
			}); err != nil {
				b.Fatal(err)
			}
		}
	})

	// Aggregates are folded in rather than rescanned, so this should not grow
	// with the population. Existing keys are re-subscribed, so each
	// measurement runs against a fixed one.
	b.Run("shared hostname", func(b *testing.B) {
		for _, existing := range []int{1, 10, 100, 1000} {
			b.Run(fmt.Sprintf("existing=%d", existing), func(b *testing.B) {
				scheduler := benchScheduler(4)
				ctx := context.Background()

				for i := 0; i < existing; i++ {
					if _, err := scheduler.Subscribe(ctx, fmt.Sprintf("api-%d", i), Config{
						Host:     "svc",
						Interval: 30 * time.Second,
					}); err != nil {
						b.Fatal(err)
					}
				}

				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := scheduler.Subscribe(ctx, fmt.Sprintf("api-%d", i%existing), Config{
						Host:     "svc",
						Interval: 30 * time.Second,
					}); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	})
}

// One resolution serves every API on the name, but notification is per
// subscriber, so subscriber count shows up here.
func BenchmarkPublishToSubscribers(b *testing.B) {
	for _, subscribers := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("subscribers=%d", subscribers), func(b *testing.B) {
			var toggle atomic.Bool
			full := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}

			scheduler := benchScheduler(4)
			scheduler.Lookup = func(_ context.Context, _ string) ([]string, error) {
				if toggle.Load() {
					return full[1:], nil
				}
				return full, nil
			}

			ctx := context.Background()
			for i := 0; i < subscribers; i++ {
				_, err := scheduler.Subscribe(ctx, fmt.Sprintf("api-%d", i), Config{
					Host:     "svc",
					Interval: 30 * time.Second,
					OnChange: func(*State) {},
				})
				if err != nil {
					b.Fatal(err)
				}
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				toggle.Store(i%2 == 0)
				scheduler.Refresh(ctx)
			}
		})
	}
}

// A reload storm. Subscribe and ReleaseKey both take the one scheduler mutex.
func BenchmarkSubscribeChurn(b *testing.B) {
	const hosts = 20

	scheduler := benchScheduler(4)
	ctx := context.Background()

	// Seed, so every measured Subscribe supersedes rather than creates.
	for i := 0; i < hosts*4; i++ {
		if _, err := scheduler.Subscribe(ctx, fmt.Sprintf("api-%d", i), Config{
			Host:     fmt.Sprintf("svc-%d", i%hosts),
			Interval: 30 * time.Second,
		}); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("api-%d", i%(hosts*4))
			if _, err := scheduler.Subscribe(ctx, key, Config{
				Host:     fmt.Sprintf("svc-%d", i%hosts),
				Interval: 30 * time.Second,
			}); err != nil {
				b.Fatal(err)
			}
			i++
		}
	})
}

// BenchmarkRescanOnExtremeDeparture is the case the aggregates cannot fold: the
// sole holder of a hostname's shortest interval leaves. The arrival is measured
// with the departure, since timing them apart costs a ReadMemStats per
// iteration; the fold is constant time and the rescan is what grows.
func BenchmarkRescanOnExtremeDeparture(b *testing.B) {
	for _, existing := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("existing=%d", existing), func(b *testing.B) {
			scheduler := benchScheduler(4)
			ctx := context.Background()

			for i := 0; i < existing; i++ {
				if _, err := scheduler.Subscribe(ctx, fmt.Sprintf("api-%d", i), Config{
					Host:     "svc",
					Interval: 30 * time.Second,
				}); err != nil {
					b.Fatal(err)
				}
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := scheduler.Subscribe(ctx, "shortest", Config{
					Host:     "svc",
					Interval: MinInterval,
				}); err != nil {
					b.Fatal(err)
				}

				scheduler.ReleaseKey("shortest")
			}
		})
	}
}

// BenchmarkLoopScan is what one iteration of the scheduler loop holds the lock
// for. Both scans walk the same map, so replacing either alone halves nothing.
func BenchmarkLoopScan(b *testing.B) {
	for _, hosts := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprintf("hosts=%d", hosts), func(b *testing.B) {
			scheduler := benchScheduler(4)
			ctx := context.Background()

			for i := 0; i < hosts; i++ {
				if _, err := scheduler.Subscribe(ctx, fmt.Sprintf("api-%d", i), Config{
					Host:     fmt.Sprintf("svc-%d", i),
					Interval: time.Hour,
				}); err != nil {
					b.Fatal(err)
				}
			}
			// Take them out of the due state, which they start in.
			scheduler.Refresh(ctx)

			b.Run("dueEntries", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					scheduler.dueEntries()
				}
			})

			b.Run("nextWait", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					scheduler.nextWait()
				}
			})
		})
	}
}

// BenchmarkNormalise runs once per lookup. DNS over TCP caps an answer at the
// two byte length prefix, so 65535 bytes, around 4000 A records.
func BenchmarkNormalise(b *testing.B) {
	for _, records := range []int{4, 50, 500, 4000} {
		b.Run(fmt.Sprintf("records=%d", records), func(b *testing.B) {
			addrs := make([]string, 0, records)
			for i := records; i > 0; i-- {
				addrs = append(addrs, fmt.Sprintf("10.%d.%d.%d", i/65025, i/255%255, i%255))
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Normalise(addrs)
			}
		})
	}
}
