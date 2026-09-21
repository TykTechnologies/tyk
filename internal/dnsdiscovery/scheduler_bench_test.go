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

	// Subscribe walks the entry's subscribers, so this is O(APIs on that
	// hostname) and reloading them all is O(n²). Existing keys are
	// re-subscribed, so each measurement runs against a fixed population.
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
