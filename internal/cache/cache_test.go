package cache_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/cache"
)

func TestCache(t *testing.T) {
	t.Parallel()

	cache := cache.New(1, 1)

	assert.Equal(t, 0, cache.Count())

	cache.Set("key", "value", 1)
	assert.Equal(t, 1, cache.Count())

	cache.Set("key", "value", 0)
	assert.Equal(t, 1, cache.Count())

	val, ok := cache.Get("key")
	assert.True(t, ok)
	assert.Equal(t, "value", val.(string))

	cache.Delete("key")
	assert.Equal(t, 0, cache.Count())

	cache.Set("key", "value", 1)
	cache.Flush()
	assert.Equal(t, 0, cache.Count())

	cache.Close()
}
