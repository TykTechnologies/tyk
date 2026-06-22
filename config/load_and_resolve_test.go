package config

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TykTechnologies/storage/kv"
	"github.com/TykTechnologies/storage/kv/registry"
	"github.com/TykTechnologies/storage/kv/resolver"
	"github.com/stretchr/testify/require"
)

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
	path := writeTempConf(t, `{"secret": "kv://no-path-separator"}`)

	var conf Config
	reg, err := LoadAndResolve(t.Context(), []string{path}, &conf, nil)

	require.Error(t, err, "a malformed kv:// reference must fail startup")
	require.ErrorIs(t, err, resolver.ErrMalformedReference,
		"the underlying resolver error must be surfaced")
	require.Nil(t, reg, "no registry is returned on a resolution failure")
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
