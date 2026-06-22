package gateway

import (
	"testing"

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
