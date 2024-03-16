package user

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSessionCache(t *testing.T) {
	// Create a new session cache
	cache := NewSessionCache()

	// Test data
	testData := SessionState{
		OrgID: "Tyk",
	}

	// Test key
	testKey := "testKey"

	// Test Set method
	cache.Set(testKey, testData, 0)

	// Test Get method
	retrievedData, ok := cache.Get(testKey)

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

	// Test data
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
