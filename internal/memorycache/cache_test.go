package memorycache

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Verifies: SYS-REQ-103, SW-REQ-031
// SYS-REQ-103:idempotency:nominal
// SYS-REQ-103:boundary:boundary
// SW-REQ-031:idempotency:nominal
// SW-REQ-031:boundary:boundary
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
