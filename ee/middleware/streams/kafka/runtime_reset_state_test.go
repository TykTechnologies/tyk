package kafka

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRuntimeResetStateStoreRegistryOwnership(t *testing.T) {
	registry := NewRuntimeResetStateStoreRegistry()
	store := NewInMemoryResetStateStore()
	registration, err := registry.Configure("component", StaticResetStateStoreProvider{Store: store})
	require.NoError(t, err)
	resolved, err := registry.Resolve(context.Background(), "component")
	require.NoError(t, err)
	require.Same(t, store, resolved)
	require.True(t, registration.Remove())
	require.False(t, registration.Remove())
	_, err = registry.Resolve(context.Background(), "component")
	require.Error(t, err)
}
