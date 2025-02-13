package cache_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/cache"
)

func TestRepository(t *testing.T) {
	cache := cache.New(1, 1)

	assert.Equal(t, 0, cache.Count())

	cache.Set("key", "value", 1)
	assert.Equal(t, 1, cache.Count())

	cache.Set("key", "value", 0)
	assert.Equal(t, 1, cache.Count())

	val, ok := cache.Get("key")
	assert.True(t, ok)

	castVal, ok := val.(string)
	assert.True(t, ok)
	assert.Equal(t, "value", castVal)

	val2, ok := cache.Get("missing")
	assert.False(t, ok)
	assert.Nil(t, val2)

	cache.Delete("key")
	assert.Equal(t, 0, cache.Count())

	cache.Set("key", "value", 1)
	cache.Flush()
	assert.Equal(t, 0, cache.Count())

	cache.Set("key", "value", 1)
	assert.Equal(t, 1, cache.Count())

	cache.Close()
	assert.Equal(t, 0, cache.Count())
}
