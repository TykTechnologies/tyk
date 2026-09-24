package dnsdiscovery

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func benchScheduler(addrsPerHost int) *Scheduler {
	addrs := make([]string, 0, addrsPerHost)
	for i := 0; i < addrsPerHost; i++ {
		addrs = append(addrs, fmt.Sprintf("10.0.%d.%d", i/250, i%250+1))
	}

	return &Scheduler{
		entries: map[string]*entry{},
		subs:    map[string]*Subscription{},
		running: true, // Benchmarks drive lookups explicitly, without a background loop.
		wake:    make(chan struct{}, 1),
		Lookup: func(_ context.Context, _ string) ([]string, error) {
			return addrs, nil
		},
		Jitter: func(d time.Duration) time.Duration { return d },
	}
}

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
			scheduler.Refresh(ctx)
			before := scheduler.Lookups()

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				scheduler.Refresh(ctx)
			}
			b.StopTimer()

			b.ReportMetric(float64(scheduler.Lookups()-before)/float64(b.N), "lookups/cycle")
		})
	}
}

func BenchmarkSubscribe(b *testing.B) {
	b.Run("new hostname and release", func(b *testing.B) {
		scheduler := benchScheduler(4)
		ctx := context.Background()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sub, err := scheduler.Subscribe(ctx, "api", Config{
				Host:     "svc",
				Interval: 30 * time.Second,
			})
			if err != nil {
				b.Fatal(err)
			}
			// Bound retained state so later iterations measure the same workload.
			sub.Release()
		}
	})

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

func BenchmarkSubscribeChurn(b *testing.B) {
	const hosts = 20

	scheduler := benchScheduler(4)
	ctx := context.Background()

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

func BenchmarkLoopScan(b *testing.B) {
	newScheduler := func(b *testing.B, hosts int, due bool) *Scheduler {
		b.Helper()
		scheduler := benchScheduler(4)
		now := time.Now()
		scheduler.Now = func() time.Time { return now }
		for i := 0; i < hosts; i++ {
			sub, err := scheduler.Subscribe(b.Context(), fmt.Sprintf("api-%d", i), Config{
				Host:     fmt.Sprintf("svc-%d", i),
				Interval: time.Hour,
			})
			if err != nil {
				b.Fatal(err)
			}
			sub.entry.nextDue = now.Add(time.Hour)
			if due {
				// Distinct deadlines exercise the production sort as well as the scan.
				sub.entry.nextDue = now.Add(-time.Duration(i) * time.Millisecond)
			}
		}
		return scheduler
	}

	for _, hosts := range []int{10, 100, 1000, 10000, 100000} {
		b.Run(fmt.Sprintf("hosts=%d", hosts), func(b *testing.B) {
			for _, due := range []bool{false, true} {
				name := "launchDue/no_due"
				if due {
					name = "launchDue/saturated"
				}
				b.Run(name, func(b *testing.B) {
					scheduler := newScheduler(b, hosts, due)
					slots := scheduler.lookupSlots()
					if due {
						// Hold every slot to measure scanning and sorting a pending
						// backlog without mixing resolver goroutines into the result.
						for i := 0; i < cap(slots); i++ {
							slots <- struct{}{}
						}
					}
					ctx := b.Context()
					var workers sync.WaitGroup
					defer workers.Wait()
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if saturated := scheduler.launchDue(ctx, &workers); saturated != due {
							b.Fatalf("launchDue saturation = %t, want %t", saturated, due)
						}
					}
					b.StopTimer()
					if scheduler.Lookups() != 0 {
						b.Fatal("scan benchmark unexpectedly launched a lookup")
					}
				})
			}

			b.Run("nextWait", func(b *testing.B) {
				scheduler := newScheduler(b, hosts, false)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if wait := scheduler.nextWait(); wait != time.Hour {
						b.Fatalf("nextWait = %s, want 1h", wait)
					}
				}
			})
		})
	}
}

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
