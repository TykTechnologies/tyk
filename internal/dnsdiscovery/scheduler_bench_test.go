package dnsdiscovery

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// Benchmarks for the claim the shape rests on: refresh cost follows distinct
// hostnames rather than subscribers, which is what makes a background refresh
// affordable at gateway scale.

// benchScheduler builds a scheduler with a fixed answer per hostname and no
// background goroutine, so a benchmark measures only what it calls.
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

// BenchmarkRefreshCycle holds subscribers at 1000 and varies how many distinct
// hostnames they point at, as a deployment does with many APIs and far fewer
// Services. The time should track hosts and stay flat in subscribers. A poller
// per subscriber would cost 1000 lookups in every case here.
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

			// Report the lookups a cycle costs, which is the claim being
			// made: hostnames, not subscribers.
			b.ReportMetric(float64(hosts), "lookups/cycle")
		})
	}
}

// BenchmarkDueEntries measures the scan done on each wake to find what is due.
// Once per wake, but it grows with the number of distinct hostnames.
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

// BenchmarkSubscribe measures load rather than the request path. Every gateway
// reload runs it for every API.
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

	// Superseding a key on a name others already hold, which is what a reload
	// does, scaled by how many APIs share the name. Subscribe derives the
	// entry's interval and stale TTL by walking its subscribers, so this is
	// O(APIs on that hostname) and a reload of them all is O(n²).
	//
	// It re-subscribes existing keys rather than adding new ones, so each
	// measurement is one Subscribe against a fixed population rather than the
	// average of a set growing under the timer.
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

// BenchmarkPublishToSubscribers measures a refresh that moved the address set
// on a name several APIs share. One resolution serves them all and the
// notification is per subscriber, so this is where subscriber count shows up
// in the cost of a membership change.
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

// BenchmarkSubscribeChurn measures a reload storm: every API re-subscribes
// under its existing key while others are being released. Subscribe and
// ReleaseKey both take the one scheduler mutex, so this is what a reload costs
// a gateway with many APIs on few Services.
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
