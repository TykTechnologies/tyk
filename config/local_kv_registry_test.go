package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewLocalKVRegistry_EmptyConfigHasOnlyLocalStores(t *testing.T) {
	reg, err := NewLocalKVRegistry(t.Context(), &Config{})
	require.NoError(t, err)
	require.NotNil(t, reg)
	closeRegistry(t, reg)

	_, err = reg.GetStore("env")
	require.NoError(t, err, "env store is always present")
	_, err = reg.GetStore("file")
	require.NoError(t, err, "file store is always present")
	_, err = reg.GetStore("secrets")
	require.Error(t, err, "no secrets store when conf.Secrets is empty")
}

func TestNewLocalKVRegistry_OmitsRemoteStoresEvenWhenConfigured(t *testing.T) {
	conf := &Config{}
	conf.KV.Vault.Address = "https://vault.internal:8200"
	conf.KV.Vault.Token = "some-token"
	conf.KV.Consul.Address = "consul.internal:8500"

	reg, err := NewLocalKVRegistry(t.Context(), conf)
	require.NoError(t, err, "building the local registry must never dial vault/consul")
	require.NotNil(t, reg)
	closeRegistry(t, reg)

	_, err = reg.GetStore("vault")
	require.Error(t, err, "vault must be filtered out (local-only, no network)")
	_, err = reg.GetStore("consul")
	require.Error(t, err, "consul must be filtered out (local-only, no network)")

	_, err = reg.GetStore("env")
	require.NoError(t, err, "local stores are still present")
	_, err = reg.GetStore("file")
	require.NoError(t, err, "local stores are still present")
}

func TestNewLocalKVRegistry_SecretsStoreResolves(t *testing.T) {
	conf := &Config{Secrets: map[string]string{"db_password": "hunter2"}}

	reg, err := NewLocalKVRegistry(t.Context(), conf)
	require.NoError(t, err)
	closeRegistry(t, reg)

	store, err := reg.GetStore("secrets")
	require.NoError(t, err)

	val, err := store.Get(t.Context(), "db_password")
	require.NoError(t, err)
	require.Equal(t, "hunter2", val)
}

func TestNewLocalKVRegistry_EnvStoreUsesTykSecretPrefix(t *testing.T) {
	t.Setenv("TYK_SECRET_DBPASS", "s3cret")

	reg, err := NewLocalKVRegistry(t.Context(), &Config{})
	require.NoError(t, err)
	closeRegistry(t, reg)

	store, err := reg.GetStore("env")
	require.NoError(t, err)

	val, err := store.Get(t.Context(), "dbpass")
	require.NoError(t, err)
	require.Equal(t, "s3cret", val, "env store applies TYK_SECRET_ prefix and uppercases the key")
}

func TestNewLocalKVRegistry_RelativeBasePathSkipsFileStore(t *testing.T) {
	conf := &Config{}
	conf.KV.File.BasePath = "relative/dir" // not absolute -> file factory rejects it

	reg, err := NewLocalKVRegistry(t.Context(), conf)
	require.NoError(t, err, "an invalid optional store is skipped, not fatal")
	require.NotNil(t, reg)
	closeRegistry(t, reg)

	_, err = reg.GetStore("file")
	require.Error(t, err, "the file store is dropped when base_path is not absolute")
}
