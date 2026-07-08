package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/storage/kv"
	"github.com/TykTechnologies/storage/kv/registry"
	"github.com/TykTechnologies/storage/kv/resolver"

	"github.com/TykTechnologies/tyk/config"
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

type bypassRecorder struct{ seen *[]bool }

func (b bypassRecorder) Get(ctx context.Context, _ string) (string, error) {
	*b.seen = append(*b.seen, kv.IsCacheBypassed(ctx))
	return "cert-value", nil
}
func (b bypassRecorder) IsStandalone() bool { return true }

func TestKVResolvers_HotReloadBypassesCache(t *testing.T) {
	seen := []bool{}

	factories := map[kv.ProviderType]kv.ProviderFactory{
		"fake_vault": func(_ json.RawMessage) (kv.Provider, error) {
			return bypassRecorder{seen: &seen}, nil
		},
	}
	raw := []byte(`{"kv":{"stores":{"vault":{"type":"fake_vault","config":{}}}}}`)
	reg, err := registry.NewFromConfig(t.Context(), raw, registry.WithFactories(factories))
	require.NoError(t, err)

	conf := config.Config{}
	conf.ExternalServices.OAuth.MTLS.Enabled = true
	conf.ExternalServices.OAuth.MTLS.CertFile = "kv://vault/cert"

	gw := NewGateway(conf, t.Context())
	// Override the local-only test registry with one that has the fake vault store.
	gw.kvRegistry = reg
	gw.kvResolver = resolver.NewResolver(reg)

	require.NoError(t, gw.afterConfSetup())
	require.Len(t, gw.kvResolvers, 1, "the kv:// field must register a hot-reload closure")
	require.Equal(t, []bool{false}, seen,
		"initial resolution must NOT bypass the cache — it populates it")

	for _, resolve := range gw.kvResolvers {
		require.NoError(t, resolve())
	}

	require.Equal(t, []bool{false, true}, seen,
		"the hot-reload closure must re-resolve with a cache-bypass context")
}

func TestKVStore_Secrets(t *testing.T) {
	gw := NewGateway(config.Config{
		Secrets: map[string]string{"db_password": "hunter2", "blank": ""},
	}, t.Context())

	t.Run("present key resolves to its value", func(t *testing.T) {
		got, err := gw.kvStore("secrets://db_password")
		require.NoError(t, err)
		require.Equal(t, "hunter2", got)
	})

	t.Run("present key with empty value resolves to empty string", func(t *testing.T) {
		got, err := gw.kvStore("secrets://blank")
		require.NoError(t, err)
		require.Equal(t, "", got)
	})

	t.Run("missing key is an error (fatal-at-startup semantics)", func(t *testing.T) {
		_, err := gw.kvStore("secrets://does_not_exist")
		require.Error(t, err)
	})
}

func TestKVStore_Secrets_NoSecretsStoreConfigured(t *testing.T) {
	gw := NewGateway(config.Config{}, t.Context())

	_, err := gw.kvStore("secrets://anything")
	require.Error(t, err, "secrets:// with no secrets store configured must error")
}

func TestKVStore_Env(t *testing.T) {
	t.Setenv("TYK_SECRET_DBPASS", "s3cret")

	gw := NewGateway(config.Config{}, t.Context())

	t.Run("reads TYK_SECRET_<UPPER> via the env store", func(t *testing.T) {
		got, err := gw.kvStore("env://dbpass")
		require.NoError(t, err)
		require.Equal(t, "s3cret", got, "env:// applies the TYK_SECRET_ prefix and uppercases the key")
	})

	t.Run("missing variable resolves to empty string, no error", func(t *testing.T) {
		got, err := gw.kvStore("env://definitely_missing")
		require.NoError(t, err, "a missing env secret must not error (os.Getenv semantics)")
		require.Equal(t, "", got)
	})
}

func TestKVStore_File(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("file-content"), 0o600))

	conf := config.Config{}
	conf.KV.File.BasePath = dir
	gw := NewGateway(conf, t.Context())

	t.Run("relative path under base_path resolves to file content", func(t *testing.T) {
		got, err := gw.kvStore("file://secret.txt")
		require.NoError(t, err)
		require.Equal(t, "file-content", got)
	})

	t.Run("missing file is an error", func(t *testing.T) {
		_, err := gw.kvStore("file://nope.txt")
		require.Error(t, err)
	})
}

func TestKVStore_File_NoBasePathConfigured(t *testing.T) {
	gw := NewGateway(config.Config{}, t.Context())

	_, err := gw.kvStore("file://secret.txt")
	require.Error(t, err, "file:// with no base_path configured must error")
}

func TestKVStore_NewSyntax(t *testing.T) {
	t.Setenv("TYK_SECRET_HOST", "myhost")

	gw := NewGateway(config.Config{
		Secrets: map[string]string{"db_password": "hunter2"},
	}, t.Context())

	t.Run("kv:// whole-value reference resolves via the resolver", func(t *testing.T) {
		got, err := gw.kvStore("kv://secrets/db_password")
		require.NoError(t, err)
		require.Equal(t, "hunter2", got)
	})

	t.Run("kv://env applies the env store prefix and uppercasing", func(t *testing.T) {
		got, err := gw.kvStore("kv://env/host")
		require.NoError(t, err)
		require.Equal(t, "myhost", got, "kv://env/host reads TYK_SECRET_HOST")
	})

	t.Run("$kv{} inline token is replaced within a larger string", func(t *testing.T) {
		got, err := gw.kvStore("https://$kv{env:host}/v1")
		require.NoError(t, err)
		require.Equal(t, "https://myhost/v1", got,
			"the default case routes to the resolver, which expands inline $kv{} tokens")
	})

	t.Run("malformed kv:// reference is an error", func(t *testing.T) {
		_, err := gw.kvStore("kv://no-path-separator")
		require.Error(t, err)
	})
}

func TestKVStore_Consul(t *testing.T) {
	gw := NewGateway(config.Config{}, t.Context())
	installFakeKVStores(t, gw, map[string]map[string]string{
		"consul": {"services/redis/host": "10.0.0.5"},
	})

	t.Run("existing key resolves via the registry consul store", func(t *testing.T) {
		got, err := gw.kvStore("consul://services/redis/host")
		require.NoError(t, err)
		require.Equal(t, "10.0.0.5", got)
	})

	t.Run("missing key propagates the not-found error", func(t *testing.T) {
		_, err := gw.kvStore("consul://services/missing")
		require.Error(t, err)

		var notFound *kv.KeyNotFoundError
		require.ErrorAs(t, err, &notFound)
	})
}

func TestKVStore_Consul_StoreUnavailable(t *testing.T) {
	gw := NewGateway(config.Config{}, t.Context())

	got, err := gw.kvStore("consul://services/redis/host")
	require.NoError(t, err, "warn-and-continue: unavailable store must not error")
	require.Equal(t, "consul://services/redis/host", got,
		"the original reference is returned when the consul store is unavailable")
}

func TestKVStore_Vault(t *testing.T) {
	gw := NewGateway(config.Config{}, t.Context())
	// The fake returns the whole secret as JSON — the real vault provider's
	// contract — so the dot→fragment conversion drives field extraction.
	installFakeKVStores(t, gw, map[string]map[string]string{
		"vault": {"secret/db": `{"password":"hunter2","username":"admin"}`},
	})

	t.Run("dot notation extracts the field from the secret", func(t *testing.T) {
		got, err := gw.kvStore("vault://secret/db.password")
		require.NoError(t, err)
		require.Equal(t, "hunter2", got, "legacy path.field must resolve the field's value")
	})

	t.Run("missing field within an existing secret is an error", func(t *testing.T) {
		_, err := gw.kvStore("vault://secret/db.missing_field")
		require.Error(t, err)
	})

	t.Run("missing secret is an error", func(t *testing.T) {
		_, err := gw.kvStore("vault://secret/missing.password")
		require.Error(t, err)

		var notFound *kv.KeyNotFoundError
		require.ErrorAs(t, err, &notFound)
	})

	t.Run("key without a dot returns the whole secret JSON", func(t *testing.T) {
		got, err := gw.kvStore("vault://secret/db")
		require.NoError(t, err)
		require.JSONEq(t, `{"password":"hunter2","username":"admin"}`, got)
	})
}

func TestKVStore_Vault_StoreUnavailable(t *testing.T) {
	gw := NewGateway(config.Config{}, t.Context())

	got, err := gw.kvStore("vault://secret/db.password")
	require.NoError(t, err, "warn-and-continue: unavailable store must not error")
	require.Equal(t, "vault://secret/db.password", got,
		"the original reference is returned when the vault store is unavailable")
}
