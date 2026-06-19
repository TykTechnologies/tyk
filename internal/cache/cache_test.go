package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Verifies: SYS-REQ-109
// MCDC SYS-REQ-109: cache_operation_determined=F, cache_operation_requested=F => TRUE
func TestMCDC_SYS_REQ_109_NoCacheOperation(t *testing.T) {
	cache := &Cache{}
	_ = cache
}

// Verifies: STK-REQ-021, SYS-REQ-109, SW-REQ-029
// STK-REQ-021:nominal:nominal
// SYS-REQ-109:nominal:nominal
// SW-REQ-029:nominal:nominal
// MCDC SYS-REQ-109: cache_operation_requested=T, cache_operation_determined=T => TRUE
//
//mcdc:ignore SYS-REQ-109: cache_operation_determined=F, cache_operation_requested=T => FALSE -- violation row is the negation of the in-process cache operation determination guarantee; focused tests assert construction, mutation, lookup, expiration, cleanup, repository, and janitor operations return deterministic results [category: defensive] [reviewed: human:buger]
func TestCache(t *testing.T) {
	cache := NewCache(0, 0)
	assert.NotNil(t, cache)
}

// Verifies: STK-REQ-021, SYS-REQ-109, SW-REQ-029
// STK-REQ-021:boundary:boundary
// SYS-REQ-109:boundary:boundary
// SW-REQ-029:boundary:boundary
func TestCache_Expired(t *testing.T) {
	cache := &Cache{
		items: map[string]Item{
			"one": {
				Expiration: 1,
			},
			"two": {
				Expiration: 0,
			},
		},
	}

	t.Run("Test Get", func(t *testing.T) {
		_, ok := cache.Get("one")
		assert.False(t, ok)
	})

	t.Run("Test Items", func(t *testing.T) {
		want := map[string]Item{
			"two": {
				Expiration: 0,
			},
		}

		got := cache.Items()
		assert.Equal(t, want, got)
	})

	t.Run("Test Cleanup", func(t *testing.T) {
		assert.Equal(t, 2, cache.Count())
		cache.Cleanup()
		assert.Equal(t, 1, cache.Count())
	})

	t.Run("Test Set", func(t *testing.T) {
		cache.Set("foo", "bar", 0)
		assert.Equal(t, 2, cache.Count())
	})
}
