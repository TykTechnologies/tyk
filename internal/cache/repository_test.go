package cache_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/cache"
)

func TestRepository(t *testing.T) {
	store := cache.New(1, 1)

	assert.Equal(t, 0, store.Count())

	store.Set("key", "value", 1)
	assert.Equal(t, 1, store.Count())

	store.Set("key", "value", 0)
	assert.Equal(t, 1, store.Count())

	val, ok := store.Get("key")
	assert.True(t, ok)

	castVal, ok := val.(string)
	assert.True(t, ok)
	assert.Equal(t, "value", castVal)

	val2, ok := store.Get("missing")
	assert.False(t, ok)
	assert.Nil(t, val2)

	store.Delete("key")
	assert.Equal(t, 0, store.Count())

	store.Set("key", "value", 1)
	store.Flush()
	assert.Equal(t, 0, store.Count())

	store.Set("key", "value", 1)
	assert.Equal(t, 1, store.Count())

	store.Close()
	assert.Equal(t, 0, store.Count())
}
