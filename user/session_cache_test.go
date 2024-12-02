package user

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSessionCache(t *testing.T) {
	testData := SessionState{
		OrgID: "Tyk",
	}
	testKey := "testKey"

	// Create a new session cache, set value for testKey
	cache := NewSessionCache()
	cache.Set(testKey, testData, 0)

	// Test Get
	retrievedData, ok := cache.Get(testKey)
	assert.True(t, ok)
	assert.Equal(t, retrievedData.OrgID, testData.OrgID)

	retrievedData, ok = cache.Get(testKey)
	assert.True(t, ok)
	assert.Equal(t, retrievedData.OrgID, testData.OrgID)

	// Test non-existent key
	nonExistentKey := "nonExistentKey"
	retrievedData, ok = cache.Get(nonExistentKey)
	assert.Nil(t, retrievedData)
	assert.False(t, ok)
}

func TestSessionCache_leaks(t *testing.T) {
	before := runtime.NumGoroutine()

	testData := SessionState{
		OrgID: "Tyk",
	}

	// Create session cache object
	for i := 0; i < 10; i++ {
		cache := NewSessionCache()
		cache.Set("k", testData, 0)
		cache = nil
	}

	// Wait a bit and trigger GC
	time.Sleep(time.Second)
	runtime.GC()

	// Assert on goroutine count
	after := runtime.NumGoroutine()

	if before < after {
		t.Errorf("Goroutine leak, was: %d, after reload: %d", before, after)
	}
}

func BenchmarkSessionState_Get(b *testing.B) {
	testData := SessionState{
		OrgID: "Tyk",
	}
	testKey := "testKey"

	cache := NewSessionCache()
	cache.Set(testKey, testData, 60)

	b.ResetTimer()

	// Test Get method
	for i := 0; i < b.N; i++ {
		r, ok := cache.Get(testKey)
		assert.True(b, ok)
		assert.Equal(b, testData.OrgID, r.OrgID)
	}
}

func BenchmarkSessionState_Set(b *testing.B) {
	testData := SessionState{
		OrgID: "Tyk",
	}
	testKey := "testKey"

	cache := NewSessionCache()

	b.ResetTimer()

	// Test Set method
	for i := 0; i < b.N; i++ {
		cache.Set(testKey, testData, 0)
	}
}
