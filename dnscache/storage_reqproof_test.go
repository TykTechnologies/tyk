package dnscache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Verifies: SW-REQ-035
// SW-REQ-035:nominal:nominal
// SW-REQ-035:boundary:nominal
// SW-REQ-035:error_handling:nominal
// SW-REQ-035:error_handling:negative
func TestDnsCacheStorageRequirement(t *testing.T) {
	storage := NewDnsCacheStorage(time.Minute, -1)
	defer storage.Clear()

	t.Run("stores lists deletes and clears address records", func(t *testing.T) {
		storage.Set("cached.example.", []string{"10.0.0.1", "10.0.0.2"})

		item, ok := storage.Get("cached.example.")
		require.True(t, ok)
		require.ElementsMatch(t, []string{"10.0.0.1", "10.0.0.2"}, item.Addrs)

		items := storage.Items(false)
		require.Contains(t, items, "cached.example.")
		require.ElementsMatch(t, item.Addrs, items["cached.example."].Addrs)

		storage.Delete("cached.example.")
		_, ok = storage.Get("cached.example.")
		require.False(t, ok)

		storage.Set("clear.example.", []string{"10.0.0.3"})
		storage.Clear()
		require.Empty(t, storage.Items(false))
	})

	t.Run("rejects empty host lookup", func(t *testing.T) {
		addrs, err := storage.FetchItem("")
		require.Error(t, err)
		require.Nil(t, addrs)
	})

	t.Run("caches successful lookups", func(t *testing.T) {
		const goodHost = "localhost."

		addrs, err := storage.FetchItem(goodHost)
		require.NoError(t, err)
		require.NotEmpty(t, addrs)

		item, ok := storage.Get(goodHost)
		require.True(t, ok)
		require.ElementsMatch(t, addrs, item.Addrs)
	})
}
