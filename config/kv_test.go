package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TykTechnologies/storage/kv"
	"github.com/TykTechnologies/storage/kv/registry"
	"github.com/TykTechnologies/storage/kv/resolver"
	"github.com/stretchr/testify/require"
)

func TestLoadAndResolve_ResolvesKVReferenceFromSecretsStore(t *testing.T) {
	path := writeTempConf(t, `{
		"secret": "kv://secrets/db_password",
		"secrets": {"db_password": "hunter2"}
	}`)

	var conf Config
	reg, err := LoadAndResolve(t.Context(), []string{path}, &conf, nil)
	require.NoError(t, err)
	require.NotNil(t, reg, "a usable registry must be returned")
	closeRegistry(t, reg)

	require.Equal(t, "hunter2", conf.Secret,
		"the kv:// reference must be replaced by the resolved secret value")
}

func TestLoadAndResolve_SnapshotRetainsUnresolvedReferences(t *testing.T) {
	path := writeTempConf(t, `{
		"secret": "kv://secrets/db_password",
		"secrets": {"db_password": "hunter2"}
	}`)

	var conf Config
	reg, err := LoadAndResolve(t.Context(), []string{path}, &conf, nil)
	require.NoError(t, err)
	closeRegistry(t, reg)

	require.Equal(t, "hunter2", conf.Secret, "the live config holds the resolved value")
	require.NotEmpty(t, conf.Private.UnresolvedConfig, "the pre-resolution snapshot must be captured")

	var snapshot Config
	require.NoError(t, json.Unmarshal(conf.Private.UnresolvedConfig, &snapshot))
	require.Equal(t, "kv://secrets/db_password", snapshot.Secret,
		"the snapshot must retain the original, unresolved reference")
}

func TestLoadAndResolve_EnvReferenceUsesTykSecretPrefix(t *testing.T) {
	t.Setenv("TYK_SECRET_DBPASS", "s3cret")

	path := writeTempConf(t, `{"secret": "kv://env/dbpass"}`)

	var conf Config
	reg, err := LoadAndResolve(t.Context(), []string{path}, &conf, nil)
	require.NoError(t, err)
	closeRegistry(t, reg)

	require.Equal(t, "s3cret", conf.Secret,
		"kv://env/dbpass must read TYK_SECRET_DBPASS")
}

func TestLoadAndResolve_MissingEnvVarResolvesToEmptyWithoutError(t *testing.T) {
	os.Unsetenv("TYK_SECRET_DEFINITELY_MISSING")

	path := writeTempConf(t, `{"secret": "kv://env/definitely_missing"}`)

	var conf Config
	reg, err := LoadAndResolve(t.Context(), []string{path}, &conf, nil)
	require.NoError(t, err, "a missing env secret must not fail startup")
	closeRegistry(t, reg)

	require.Equal(t, "", conf.Secret, "a missing env var resolves to the empty string")
}

func TestLoadAndResolve_UserDefinedStoreFromConfigFileResolves(t *testing.T) {
	path := writeTempConf(t, `{
		"secret": "kv://myvals/token",
		"kv": {
			"stores": {
				"myvals": {"type": "inline", "config": {"data": {"token": "xyz"}}}
			}
		}
	}`)

	var conf Config
	reg, err := LoadAndResolve(t.Context(), []string{path}, &conf, nil)
	require.NoError(t, err)
	closeRegistry(t, reg)

	require.Equal(t, "xyz", conf.Secret,
		"a store defined under kv.stores must survive the round-trip and resolve")
}

func TestLoadAndResolve_InjectedFactoryResolvesCustomStore(t *testing.T) {
	const customType kv.ProviderType = "fake_secrets_manager"

	factories := map[kv.ProviderType]kv.ProviderFactory{
		customType: func(_ json.RawMessage) (kv.Provider, error) {
			return fakeProvider{value: "from-ee-provider"}, nil
		},
	}

	path := writeTempConf(t, `{
		"secret": "kv://myfake/whatever",
		"kv": {
			"stores": {
				"myfake": {"type": "fake_secrets_manager", "config": {}}
			}
		}
	}`)

	var conf Config
	reg, err := LoadAndResolve(t.Context(), []string{path}, &conf, factories)
	require.NoError(t, err)
	closeRegistry(t, reg)

	require.Equal(t, "from-ee-provider", conf.Secret,
		"an injected factory must be available to resolve its store type")
}

func TestLoadAndResolve_MalformedReferenceFailsStartup(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "kv:// without a path separator",
			raw:  `{"secret": "kv://no-path-separator"}`,
		},
		{
			name: "unclosed $kv{ token",
			raw:  `{"secret": "$kv{unclosed"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTempConf(t, tc.raw)

			var conf Config
			reg, err := LoadAndResolve(t.Context(), []string{path}, &conf, nil)

			require.Error(t, err, "a malformed reference must fail startup")
			require.ErrorIs(t, err, resolver.ErrMalformedReference,
				"the underlying resolver error must be surfaced")
			require.Nil(t, reg, "no registry is returned on a resolution failure")
		})
	}
}

func TestLoadAndResolve_NoKVReferencesLeavesConfigUnchanged(t *testing.T) {
	path := writeTempConf(t, `{"secret": "plain-value"}`)

	var conf Config
	reg, err := LoadAndResolve(t.Context(), []string{path}, &conf, nil)
	require.NoError(t, err)
	require.NotNil(t, reg)
	closeRegistry(t, reg)

	require.Equal(t, "plain-value", conf.Secret, "a value with no kv reference is left as-is")

	_, err = reg.GetStore("env")
	require.NoError(t, err, "the env store is always initialized")
	_, err = reg.GetStore("file")
	require.NoError(t, err, "the file store is always initialized")
}

func TestLoadAndResolve_PropagatesLoadError(t *testing.T) {
	path := writeTempConf(t, `{ this is not valid json`)

	var conf Config
	reg, err := LoadAndResolve(t.Context(), []string{path}, &conf, nil)

	require.Error(t, err, "an unparseable config file must surface the Load error")
	require.Nil(t, reg, "no registry is returned when Load fails")
}

func TestLoadAndResolve_PreservesJSONDashFields(t *testing.T) {
	path := writeTempConf(t, `{
		"secret": "kv://secrets/db_password",
		"secrets": {"db_password": "hunter2"}
	}`)

	var conf Config
	reg, err := LoadAndResolve(t.Context(), []string{path}, &conf, nil)
	require.NoError(t, err)
	closeRegistry(t, reg)

	require.Equal(t, path, conf.Private.OriginalPath,
		"a json:\"-\" field set during Load must survive the resolution round-trip")
}

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

func TestBuildKVConfig_EmptyConfig(t *testing.T) {
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

	t.Run("file store is always emitted, even without base_path", func(t *testing.T) {
		t.Parallel()

		// file is a local provider with no network init: a store with an empty
		// base_path costs nothing and, on use, rejects every Get with the
		// specific ErrBasePathRequired. That is a strictly better diagnostic
		// than the ErrStoreNotFound a caller would hit if the store were absent,
		// and it faithfully reproduces the legacy "file refs disabled, every key
		// rejected" behavior.
		file, ok := stores["file"]
		require.True(t, ok, "file store must always be emitted")
		require.Equal(t, kv.File, file.Type)

		cfg := decodeConfig(t, file.Config)
		require.Equal(t, "", cfg["base_path"],
			"an unset base_path is passed through as empty, not dropped")
	})

	t.Run("env and file are the only stores emitted on an empty config", func(t *testing.T) {
		t.Parallel()

		require.NotContains(t, stores, "secrets")
		require.NotContains(t, stores, "vault")
		require.NotContains(t, stores, "consul")
		require.Len(t, stores, 2, "empty config emits exactly the env and file stores")
	})
}

func TestBuildKVConfig_FileBasePath(t *testing.T) {
	t.Parallel()

	conf := &Config{}
	conf.KV.File.BasePath = "/etc/tyk/secrets"

	stores := buildKVConfig(conf)

	file, ok := stores["file"]
	require.True(t, ok, "file store must be emitted when base_path is set")
	require.Equal(t, kv.File, file.Type)

	cfg := decodeConfig(t, file.Config)
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

	t.Run("a present key with an empty-string value is preserved, not dropped", func(t *testing.T) {
		t.Parallel()

		// The inline provider distinguishes a missing key (KeyNotFound) from a
		// key present with value "". Promotion must keep that distinction so
		// secrets://blank resolves to "" rather than erroring.
		conf := &Config{Secrets: map[string]string{"blank": ""}}

		stores := buildKVConfig(conf)

		cfg := decodeConfig(t, stores["secrets"].Config)
		data, ok := cfg["data"].(map[string]any)
		require.True(t, ok)
		require.Contains(t, data, "blank", "an empty-valued secret must still be present")
		require.Equal(t, "", data["blank"])
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

	t.Run("unset timeout serializes to \"0s\", never int64 nanoseconds", func(t *testing.T) {
		t.Parallel()

		conf := &Config{}
		conf.KV.Vault.Address = "https://vault.internal:8200"

		stores := buildKVConfig(conf)

		cfg := decodeConfig(t, stores["vault"].Config)
		require.Equal(t, "0s", cfg["timeout"],
			"a zero time.Duration must still marshal as the \"0s\" string the provider parses")
	})

	t.Run("agent_address is included to the marshaled vault config", func(t *testing.T) {
		t.Parallel()

		conf := &Config{}
		conf.KV.Vault.Address = "https://vault.internal:8200"
		conf.KV.Vault.AgentAddress = "http://127.0.0.1:8200"

		stores := buildKVConfig(conf)

		cfg := decodeConfig(t, stores["vault"].Config)
		require.Equal(t, conf.KV.Vault.AgentAddress, cfg["agent_address"])
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

	t.Run("non-wait_time fields survive the alias marshaling", func(t *testing.T) {
		t.Parallel()

		// marshalConsulConfig embeds an alias of ConsulConfig and shadows only
		// WaitTime. This guards that the alias trick doesn't silently drop the
		// other fields (scheme, datacenter, token, the nested http_auth object).
		conf := &Config{}
		conf.KV.Consul.Address = "consul.internal:8500"
		conf.KV.Consul.Scheme = "https"
		conf.KV.Consul.Datacenter = "dc1"
		conf.KV.Consul.Token = "consul-token"
		conf.KV.Consul.HttpAuth.Username = "user"
		conf.KV.Consul.HttpAuth.Password = "pass"

		stores := buildKVConfig(conf)

		cfg := decodeConfig(t, stores["consul"].Config)
		require.Equal(t, "https", cfg["scheme"])
		require.Equal(t, "dc1", cfg["datacenter"])
		require.Equal(t, "consul-token", cfg["token"])

		auth, ok := cfg["http_auth"].(map[string]any)
		require.True(t, ok, "nested http_auth object must survive marshaling")
		require.Equal(t, "user", auth["username"])
		require.Equal(t, "pass", auth["password"])
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

	require.ElementsMatch(
		t,
		[]string{"env", "file", "secrets", "vault", "consul"},
		keysOf(stores),
	)
}

// writeTempConf writes raw as a tyk.conf file in a fresh temp dir and returns
// its path. Each test gets its own file so they never collide.
func writeTempConf(t *testing.T, raw string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "tyk.conf")
	require.NoError(t, os.WriteFile(path, []byte(raw), 0o644))

	return path
}

// closeRegistry registers a cleanup that closes reg if it was created.
// It uses a non-cancelled context derived from the test context, because
// t.Context() is already cancelled by the time cleanups run.
func closeRegistry(t *testing.T, reg *registry.Registry) {
	t.Helper()

	t.Cleanup(func() {
		if reg != nil {
			_ = reg.Close(context.WithoutCancel(t.Context()))
		}
	})
}

// fakeProvider is a stand-in for an enterprise provider: it ignores the key and
// returns a fixed value. It is Standalone so the registry doesn't wrap it in a
// cache, keeping the test focused on the factory-injection path.
type fakeProvider struct{ value string }

func (f fakeProvider) Get(_ context.Context, _ string) (string, error) { return f.value, nil }
func (f fakeProvider) IsStandalone() bool                              { return true }

// decodeConfig unmarshals a store's raw Config blob into a generic map for
// field-level assertions.
func decodeConfig(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()

	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))

	return m
}

func keysOf(m map[string]kv.StoreConfig) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	return keys
}

// BenchmarkLoadAndResolve measures the gateway's real startup resolution path
// (Load + FillEnv + registry bootstrap + strict ResolveAll + unmarshal) as a
// function of KV reference count.
func BenchmarkLoadAndResolve(b *testing.B) {
	b.Setenv("TYK_SECRET_BENCH_VAL", "bench-value")

	for _, n := range []int{0, 20, 50, 100} {
		secrets := make(map[string]string, n)
		for i := 0; i < n; i++ {
			secrets[fmt.Sprintf("key_%d", i)] = "kv://env/bench_val"
		}

		doc, err := json.Marshal(map[string]any{"secrets": secrets})
		require.NoError(b, err)

		path := filepath.Join(b.TempDir(), "tyk.conf")
		require.NoError(b, os.WriteFile(path, doc, 0o644))

		b.Run(fmt.Sprintf("refs=%d", n), func(b *testing.B) {
			for b.Loop() {
				var conf Config

				reg, err := LoadAndResolve(context.Background(), []string{path}, &conf, nil)
				if err != nil {
					b.Fatal(err)
				}

				_ = reg.Close(context.Background())
			}
		})
	}
}
