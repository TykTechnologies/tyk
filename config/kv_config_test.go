package config

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/TykTechnologies/storage/kv"
	"github.com/stretchr/testify/require"
)

// decodeConfig unmarshals a store's raw Config blob into a generic map for
// field-level assertions.
func decodeConfig(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()

	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))

	return m
}

func TestBuildKVConfig_AlwaysEmitted(t *testing.T) {
	t.Parallel()

	stores := buildKVConfig(&Config{})

	t.Run("env store is always emitted with prefix and uppercase", func(t *testing.T) {
		t.Parallel()

		env, ok := stores["env"]
		require.True(t, ok, "env store must always be emitted")
		require.Equal(t, kv.Env, env.Type)

		cfg := decodeConfig(t, env.Config)
		require.Equal(t, "TYK_SECRET_", cfg["prefix"], "legacy behavior reads TYK_SECRET_<KEY>")
		require.Equal(t, true, cfg["uppercase"], "legacy behavior uppercases the key")
	})

	t.Run("file store is always emitted, even with empty base_path", func(t *testing.T) {
		t.Parallel()

		file, ok := stores["file"]
		require.True(t, ok, "file store must always be emitted")
		require.Equal(t, kv.File, file.Type)

		cfg := decodeConfig(t, file.Config)
		require.Equal(t, "", cfg["base_path"])
	})

	t.Run("no conditional stores on an empty config", func(t *testing.T) {
		t.Parallel()

		require.NotContains(t, stores, "secrets")
		require.NotContains(t, stores, "vault")
		require.NotContains(t, stores, "consul")
		require.Len(t, stores, 2, "empty config emits exactly env and file")
	})
}

func TestBuildKVConfig_FileBasePath(t *testing.T) {
	t.Parallel()

	conf := &Config{}
	conf.KV.File.BasePath = "/etc/tyk/secrets"

	stores := buildKVConfig(conf)

	cfg := decodeConfig(t, stores["file"].Config)
	require.Equal(t, "/etc/tyk/secrets", cfg["base_path"])
}

func TestBuildKVConfig_Secrets(t *testing.T) {
	t.Parallel()

	t.Run("non-empty secrets emits an inline store named secrets", func(t *testing.T) {
		t.Parallel()

		conf := &Config{
			Secrets: map[string]string{"db_password": "hunter2", "api_key": "abc123"},
		}

		stores := buildKVConfig(conf)

		secrets, ok := stores["secrets"]
		require.True(t, ok, "store name must be 'secrets' so secrets:// references route to it")
		require.Equal(t, kv.Inline, secrets.Type, "secrets is backed by the inline provider")

		// The map must travel into the store under the inline provider's
		// "data" key so Get(\"db_password\") returns "hunter2".
		cfg := decodeConfig(t, secrets.Config)
		data, ok := cfg["data"].(map[string]any)
		require.True(t, ok, "inline config must carry a 'data' object")
		require.Equal(t, "hunter2", data["db_password"])
		require.Equal(t, "abc123", data["api_key"])
	})

	t.Run("empty secrets map emits no secrets store", func(t *testing.T) {
		t.Parallel()

		stores := buildKVConfig(&Config{Secrets: map[string]string{}})
		require.NotContains(t, stores, "secrets")
	})
}

func TestBuildKVConfig_Vault(t *testing.T) {
	t.Parallel()

	t.Run("emitted when address is set", func(t *testing.T) {
		t.Parallel()

		conf := &Config{}
		conf.KV.Vault.Address = "https://vault.internal:8200"

		stores := buildKVConfig(conf)

		vault, ok := stores["vault"]
		require.True(t, ok)
		require.Equal(t, kv.Vault, vault.Type)
		require.False(t, vault.Required, "vault is warn-and-continue (required:false)")

		cfg := decodeConfig(t, vault.Config)
		require.Equal(t, "https://vault.internal:8200", cfg["address"])
	})

	t.Run("emitted when only token is set", func(t *testing.T) {
		t.Parallel()

		conf := &Config{}
		conf.KV.Vault.Token = "hvs.sometoken"

		stores := buildKVConfig(conf)
		require.Contains(t, stores, "vault", "token alone is enough to emit the vault store")
	})

	t.Run("timeout is serialized as a duration string", func(t *testing.T) {
		t.Parallel()

		conf := &Config{}
		conf.KV.Vault.Address = "https://vault.internal:8200"
		conf.KV.Vault.Timeout = 5 * time.Second

		stores := buildKVConfig(conf)

		cfg := decodeConfig(t, stores["vault"].Config)
		require.Equal(t, "5s", cfg["timeout"],
			"VaultConfig.Timeout is time.Duration (int64 ns); the provider expects \"5s\"")
	})

	t.Run("not emitted when neither address nor token is set", func(t *testing.T) {
		t.Parallel()

		stores := buildKVConfig(&Config{})
		require.NotContains(t, stores, "vault")
	})
}

func TestBuildKVConfig_Consul(t *testing.T) {
	t.Parallel()

	t.Run("emitted when address is set", func(t *testing.T) {
		t.Parallel()

		conf := &Config{}
		conf.KV.Consul.Address = "consul.internal:8500"

		stores := buildKVConfig(conf)

		consul, ok := stores["consul"]
		require.True(t, ok)
		require.Equal(t, kv.Consul, consul.Type)
		require.False(t, consul.Required, "consul is warn-and-continue (required:false)")

		cfg := decodeConfig(t, consul.Config)
		require.Equal(t, "consul.internal:8500", cfg["address"])
	})

	t.Run("wait_time is serialized as a duration string", func(t *testing.T) {
		t.Parallel()

		conf := &Config{}
		conf.KV.Consul.Address = "consul.internal:8500"
		conf.KV.Consul.WaitTime = 5 * time.Second

		stores := buildKVConfig(conf)

		cfg := decodeConfig(t, stores["consul"].Config)
		require.Equal(t, "5s", cfg["wait_time"],
			"ConsulConfig.WaitTime is time.Duration (int64 ns); the provider expects \"5s\"")
	})

	t.Run("not emitted without an address", func(t *testing.T) {
		t.Parallel()

		conf := &Config{}
		conf.KV.Consul.Token = "some-token" // token without address is not enough

		stores := buildKVConfig(conf)
		require.NotContains(t, stores, "consul")
	})
}

func TestBuildKVConfig_FullConfig(t *testing.T) {
	t.Parallel()

	// All blocks set: every store should appear exactly once.
	conf := &Config{
		Secrets: map[string]string{"k": "v"},
	}
	conf.KV.File.BasePath = "/etc/tyk/secrets"
	conf.KV.Vault.Address = "https://vault.internal:8200"
	conf.KV.Consul.Address = "consul.internal:8500"

	stores := buildKVConfig(conf)

	require.ElementsMatch(t,
		[]string{"env", "file", "secrets", "vault", "consul"},
		keysOf(stores),
	)
}

func keysOf(m map[string]kv.StoreConfig) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	return keys
}
