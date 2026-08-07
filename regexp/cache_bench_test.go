package regexp

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// BenchmarkCache_HitParallel measures expirable.LRU mutex contention under
// concurrent hot-path reads with the cache saturated to capacity.
func BenchmarkCache_HitParallel(b *testing.B) {
	const cap = 5000
	c := newCacheWithSize(0, cap, true, "", nil)
	keys := make([]string, cap)
	for i := 0; i < cap; i++ {
		keys[i] = fmt.Sprintf("key-%d", i)
		c.add(keys[i], keys[i])
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		for pb.Next() {
			_, _ = c.getString(keys[r.Intn(cap)])
		}
	})
}

// BenchmarkCache_MissAndAdd_Saturated measures eviction overhead: each Add
// triggers an LRU eviction once the cache is at capacity.
func BenchmarkCache_MissAndAdd_Saturated(b *testing.B) {
	const cap = 5000
	c := newCacheWithSize(0, cap, true, "", nil)
	for i := 0; i < cap; i++ {
		k := fmt.Sprintf("seed-%d", i)
		c.add(k, k)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			k := fmt.Sprintf("bench-%d-%d", i, time.Now().UnixNano())
			c.add(k, k)
			i++
		}
	})
}
