package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCache(t *testing.T) {
	cache := NewCache(0, 0)
	assert.NotNil(t, cache)
}

func TestCache_Expired(t *testing.T) {
	cache := &Cache{
		items: map[string]Item{
			"one": Item{
				Expiration: 1,
			},
			"two": Item{
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
			"two": Item{
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
