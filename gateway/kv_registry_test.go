package gateway

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/TykTechnologies/storage/kv"
	"github.com/TykTechnologies/storage/kv/registry"
	"github.com/TykTechnologies/tyk/config"
	"github.com/stretchr/testify/require"
)

func TestNewGateway_EstablishesKVRegistryInvariant(t *testing.T) {
	gw := NewGateway(config.Config{}, t.Context())

	require.NotNil(t, gw.kvRegistry, "NewGateway must always establish a registry")
	require.NotNil(t, gw.kvResolver, "NewGateway must always establish a resolver")

	_, err := gw.kvRegistry.GetStore("env")
	require.NoError(t, err, "the test-mode registry carries the local env store")
	_, err = gw.kvRegistry.GetStore("file")
	require.NoError(t, err, "the test-mode registry carries the local file store")
}

func TestEnsureKVRegistry_BuildsWhenNil(t *testing.T) {
	gw := &Gateway{ctx: t.Context()}
	require.Nil(t, gw.kvRegistry)

	require.NoError(t, gw.ensureKVRegistry(config.Config{}))

	require.NotNil(t, gw.kvRegistry, "a nil registry must be built")
	require.NotNil(t, gw.kvResolver, "a nil resolver must be built")
}

func TestEnsureKVRegistry_DoesNotClobberExisting(t *testing.T) {
	existing, err := config.NewLocalKVRegistry(t.Context(), &config.Config{})
	require.NoError(t, err)

	gw := &Gateway{ctx: t.Context(), kvRegistry: existing}

	require.NoError(t, gw.ensureKVRegistry(config.Config{}))

	require.Same(t, existing, gw.kvRegistry,
		"an already-installed registry must not be replaced")
}

type kvCloserStub struct{ closed *atomic.Bool }

func (c kvCloserStub) Get(_ context.Context, _ string) (string, error) { return "", nil }
func (c kvCloserStub) IsStandalone() bool                              { return true }
func (c kvCloserStub) Close(_ context.Context) error {
	c.closed.Store(true)
	return nil
}

func TestCloseKVRegistry_NilIsSafe(t *testing.T) {
	gw := &Gateway{}
	require.Nil(t, gw.kvRegistry)

	require.NotPanics(t, func() { gw.closeKVRegistry(t.Context()) })
}

func TestCloseKVRegistry_ClosesProviderConnections(t *testing.T) {
	var closed atomic.Bool

	factories := map[kv.ProviderType]kv.ProviderFactory{
		"fake_closer": func(_ json.RawMessage) (kv.Provider, error) {
			return kvCloserStub{closed: &closed}, nil
		},
	}

	raw := []byte(`{"kv":{"stores":{"remote":{"type":"fake_closer","config":{}}}}}`)
	reg, err := registry.NewFromConfig(t.Context(), raw, registry.WithFactories(factories))
	require.NoError(t, err)

	gw := &Gateway{kvRegistry: reg}
	gw.closeKVRegistry(t.Context())

	require.True(t, closed.Load(),
		"closeKVRegistry must forward Close to the registry's providers")
}
