package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Verifies: STK-REQ-021, SYS-REQ-109, SW-REQ-029
// STK-REQ-021:nominal:nominal
// SYS-REQ-109:nominal:nominal
// SW-REQ-029:nominal:nominal
// MCDC SYS-REQ-109: cache_operation_requested=T, cache_operation_determined=T => TRUE
func TestCache(t *testing.T) {
	cache := NewCache(0, 0)
	assert.NotNil(t, cache)
}

// Verifies: STK-REQ-021, SYS-REQ-109, SW-REQ-029
// STK-REQ-021:boundary:boundary
// SYS-REQ-109:boundary:boundary
// SW-REQ-029:boundary:nominal
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
