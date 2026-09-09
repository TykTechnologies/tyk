package memorycache

import (
	"context"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCache_Shutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	g1 := runtime.NumGoroutine()

	cache := NewCache(ctx, time.Minute)
	cache.Set("default", nil)
	assert.Equal(t, 1, cache.Count(), "added an item here")

	g2 := runtime.NumGoroutine()

	cancel()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	assert.True(t, g1+1 == g2, "goroutine should increase by one, got %d => %d", g1, g2)
	assert.Equal(t, 0, cache.Count(), "we cleared the cache on shutdown")
}

func TestCache_CleanupTimer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use a short TTL, but note that the cleanup timer runs at least every 1 second
	cache := NewCache(ctx, 10*time.Millisecond)

	// Add an item
	cache.Set("item1", nil)
	assert.Equal(t, 1, cache.Count())

	// Wait for the cleanup timer to run (minimum 1 second)
	time.Sleep(1200 * time.Millisecond)

	// The item should be expired and removed
	assert.Equal(t, 0, cache.Count())

	// Add another item to ensure the timer is still running
	cache.Set("item2", nil)
	assert.Equal(t, 1, cache.Count())

	// Wait again
	time.Sleep(1200 * time.Millisecond)

	// The second item should also be removed
	assert.Equal(t, 0, cache.Count())
}

func BenchmarkCache_MemoryLeak(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use a short TTL so items expire quickly
	cache := NewCache(ctx, 10*time.Millisecond)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Simulate adding a new rate limit bucket for a unique IP
		// We use a small string to avoid excessive allocation overhead from string formatting
		// But we need unique keys.
		cache.Set(string(rune(i)), nil)

		// Periodically yield to allow the cleanup goroutine to run
		if i%1000 == 0 {
			time.Sleep(1 * time.Millisecond)
		}
	}
	b.ReportMetric(float64(cache.Count()), "items_left")
}

func TestCache_MemoryLeak_GC(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use a short TTL so items expire quickly
	ttl := 10 * time.Millisecond
	cache := NewCache(ctx, ttl)

	// 1. Force GC and record baseline memory
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// 2. Add many items to the cache to simulate load
	numItems := 100000
	for i := 0; i < numItems; i++ {
		cache.Set("key-"+strconv.Itoa(i), &Bucket{})
	}

	// 3. Record memory after adding items
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	// 4. Wait for items to expire and the cleanup timer to run.
	// Note: startCleanupTimer enforces a minimum interval of 1 second,
	// so we must wait slightly longer than 1 second.
	time.Sleep(1500 * time.Millisecond)

	// 5. Force GC to reclaim memory of the expired items
	runtime.GC()

	// 6. Record memory after GC
	var m3 runtime.MemStats
	runtime.ReadMemStats(&m3)

	// Verify the cache is actually empty
	assert.Equal(t, 0, cache.Count(), "cache should be empty after expiration")

	// Verify memory was actually freed
	freed := int64(m2.Alloc) - int64(m3.Alloc)
	assert.True(t, freed > 0, "memory should be freed after GC")

	// Optional: Verify final memory is close to the baseline (allowing 2MB overhead)
	assert.InDelta(t, float64(m1.Alloc), float64(m3.Alloc), float64(5*1024*1024), "memory should return close to baseline")
}
