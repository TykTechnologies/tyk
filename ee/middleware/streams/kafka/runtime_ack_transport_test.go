package kafka

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuntimeAckTransportRegistryLifecycle(t *testing.T) {
	registry := NewRuntimeAckTransportRegistry()
	transport := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{})
	registration, err := registry.Configure("component", StaticDurableAckTransportProvider{Transport: transport})
	require.NoError(t, err)
	resolved, err := registry.Resolve(context.Background(), "component")
	require.NoError(t, err)
	assert.Same(t, transport, resolved)
	_, err = registry.Configure("component", StaticDurableAckTransportProvider{Transport: transport})
	assert.Error(t, err)
	assert.True(t, registration.Remove())
	assert.False(t, registration.Remove())
	_, err = registry.Resolve(context.Background(), "component")
	assert.Error(t, err)
}

func TestRuntimeAckTransportRegistryStaleRemoval(t *testing.T) {
	registry := NewRuntimeAckTransportRegistry()
	transport := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{})
	stale, err := registry.Configure("component", StaticDurableAckTransportProvider{Transport: transport})
	require.NoError(t, err)
	require.True(t, stale.Remove())
	current, err := registry.Configure("component", StaticDurableAckTransportProvider{Transport: transport})
	require.NoError(t, err)

	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() { defer wait.Done(); stale.Remove() }()
	}
	wait.Wait()
	resolved, err := registry.Resolve(context.Background(), "component")
	require.NoError(t, err)
	assert.Same(t, transport, resolved)
	assert.True(t, current.Remove())
}
