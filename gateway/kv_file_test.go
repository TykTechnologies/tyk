package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
)

// TestKVStoreFileScheme tests that kvStore() resolves file:// URIs (Context 1).
func TestKVStoreFileScheme(t *testing.T) {
	t.Run("no base_path configured", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		t.Run("absolute file:// rejected without base_path", func(t *testing.T) {
			dir := t.TempDir()
			f := filepath.Join(dir, "secret")
			require.NoError(t, os.WriteFile(f, []byte("super-secret\n"), 0600))

			_, err := ts.Gw.kvStore("file://" + f)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "base_path")
		})

		t.Run("relative file:// rejected without base_path", func(t *testing.T) {
			_, err := ts.Gw.kvStore("file://just-a-name")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "base_path")
		})

		t.Run("passes through non-file values unchanged", func(t *testing.T) {
			val, err := ts.Gw.kvStore("plain-string")
			require.NoError(t, err)
			assert.Equal(t, "plain-string", val)
		})
	})

	t.Run("relative key resolved via base_path", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "node-secret"), []byte("my-node-secret"), 0600))

		ts := StartTest(func(conf *config.Config) {
			conf.KV.File.BasePath = dir
		})
		defer ts.Close()

		t.Run("resolves relative key under base_path", func(t *testing.T) {
			val, err := ts.Gw.kvStore("file://node-secret")
			require.NoError(t, err)
			assert.Equal(t, "my-node-secret", val)
		})

		t.Run("absolute path rejected when base_path is set", func(t *testing.T) {
			f := filepath.Join(dir, "node-secret")
			_, err := ts.Gw.kvStore("file://" + f)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "absolute path")
		})

		t.Run("absolute path to file outside base_path is rejected", func(t *testing.T) {
			outside := t.TempDir()
			secret := filepath.Join(outside, "passwd")
			require.NoError(t, os.WriteFile(secret, []byte("root:x:0:0"), 0600))

			_, err := ts.Gw.kvStore("file://" + secret)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "absolute path")
		})

		t.Run("dotdot traversal rejected even when base_path is set", func(t *testing.T) {
			_, err := ts.Gw.kvStore("file://../etc/passwd")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "traversal")
		})
	})
}

// TestFileKVHotReload verifies that kvResolvers closures re-read the file on
// every hot reload and pick up K8s AtomicWriter secret rotations.
func TestFileKVHotReload(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	caFile := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(certFile, []byte("cert-v1"), 0600))
	require.NoError(t, os.WriteFile(keyFile, []byte("key-v1"), 0600))
	require.NoError(t, os.WriteFile(caFile, []byte("ca-v1"), 0600))

	// file:// references require base_path; keys are relative to it.
	cfg := config.Config{
		ExternalServices: config.ExternalServiceConfig{
			OAuth: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled:  true,
					CertFile: "file://tls.crt",
					KeyFile:  "file://tls.key",
					CAFile:   "file://ca.crt",
				},
			},
		},
	}
	cfg.KV.File.BasePath = dir

	gw := NewGateway(cfg, t.Context())

	require.NoError(t, gw.afterConfSetup())

	// Startup: all three fields resolved from files.
	conf := gw.GetConfig()
	assert.Equal(t, "cert-v1", conf.ExternalServices.OAuth.MTLS.CertFile)
	assert.Equal(t, "key-v1", conf.ExternalServices.OAuth.MTLS.KeyFile)
	assert.Equal(t, "ca-v1", conf.ExternalServices.OAuth.MTLS.CAFile)
	assert.Len(t, gw.kvResolvers, 3)

	// Simulate cert rotation: overwrite the files.
	require.NoError(t, os.WriteFile(certFile, []byte("cert-v2"), 0600))
	require.NoError(t, os.WriteFile(keyFile, []byte("key-v2"), 0600))
	require.NoError(t, os.WriteFile(caFile, []byte("ca-v2"), 0600))

	// Hot reload: closures must re-read the files and update the live config.
	for _, resolve := range gw.kvResolvers {
		require.NoError(t, resolve())
	}

	conf = gw.GetConfig()
	assert.Equal(t, "cert-v2", conf.ExternalServices.OAuth.MTLS.CertFile)
	assert.Equal(t, "key-v2", conf.ExternalServices.OAuth.MTLS.KeyFile)
	assert.Equal(t, "ca-v2", conf.ExternalServices.OAuth.MTLS.CAFile)
}

func TestResolveFileKV(t *testing.T) {
	t.Run("reads plain file contents", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("my-secret-value"), 0600))

		val, err := ResolveFileKV(dir, "secret.txt")
		require.NoError(t, err)
		assert.Equal(t, "my-secret-value", val)
	})

	t.Run("strips trailing newline by default", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("my-secret-value\n"), 0600))

		val, err := ResolveFileKV(dir, "secret.txt")
		require.NoError(t, err)
		assert.Equal(t, "my-secret-value", val)
	})

	t.Run("strips trailing newline CRLF", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("my-secret-value\r\n"), 0600))

		val, err := ResolveFileKV(dir, "secret.txt")
		require.NoError(t, err)
		assert.Equal(t, "my-secret-value", val)
	})

	t.Run("preserves multi-line content except trailing newline", func(t *testing.T) {
		dir := t.TempDir()
		pem := "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJ\n-----END CERTIFICATE-----\n"
		require.NoError(t, os.WriteFile(filepath.Join(dir, "cert.pem"), []byte(pem), 0600))

		val, err := ResolveFileKV(dir, "cert.pem")
		require.NoError(t, err)
		assert.Equal(t, "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJ\n-----END CERTIFICATE-----", val)
	})

	t.Run("returns error for non-existent file under basePath", func(t *testing.T) {
		dir := t.TempDir()
		_, err := ResolveFileKV(dir, "nonexistent.txt")
		assert.Error(t, err)
	})

	t.Run("relative key without basePath returns descriptive error", func(t *testing.T) {
		_, err := ResolveFileKV("", "my-cert")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "base_path")
	})

	t.Run("absolute key without basePath returns descriptive error", func(t *testing.T) {
		_, err := ResolveFileKV("", "/etc/passwd")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "base_path")
	})

	t.Run("rejects relative basePath", func(t *testing.T) {
		_, err := ResolveFileKV("relative/base", "secret.txt")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be an absolute path")
	})

	t.Run("resolves key relative to basePath", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "api-key")
		require.NoError(t, os.WriteFile(f, []byte("the-api-key"), 0600))

		val, err := ResolveFileKV(dir, "api-key")
		require.NoError(t, err)
		assert.Equal(t, "the-api-key", val)
	})

	t.Run("rejects absolute path when basePath is set", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "secret")
		require.NoError(t, os.WriteFile(f, []byte("abs-value"), 0600))

		_, err := ResolveFileKV("/some/other/base", f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "absolute path")
	})

	t.Run("rejects absolute path even when it points inside basePath", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "secret")
		require.NoError(t, os.WriteFile(f, []byte("abs-value"), 0600))

		_, err := ResolveFileKV(dir, f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "absolute path")
	})

	t.Run("rejects dotdot traversal when basePath is set", func(t *testing.T) {
		dir := t.TempDir()
		_, err := ResolveFileKV(dir, "../etc/passwd")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "traversal")
	})

	t.Run("rejects embedded dotdot traversal", func(t *testing.T) {
		dir := t.TempDir()
		_, err := ResolveFileKV(dir, "subdir/../../etc/passwd")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "traversal")
	})

	t.Run("rejects symlink that escapes basePath after EvalSymlinks", func(t *testing.T) {
		base := t.TempDir()
		target := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(target, "passwd"), []byte("root:x:0:0"), 0600))

		// Create a symlink inside base/ pointing outside to target/passwd
		require.NoError(t, os.Symlink(filepath.Join(target, "passwd"), filepath.Join(base, "evil-link")))

		_, err := ResolveFileKV(base, "evil-link")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symlink escape")
	})

	t.Run("rejects absolute path when basePath is empty", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "secret")
		require.NoError(t, os.WriteFile(f, []byte("value"), 0600))

		_, err := ResolveFileKV("", f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "base_path")
	})

	t.Run("follows k8s AtomicWriter symlinks", func(t *testing.T) {
		// Simulate K8s secret mount:
		// /secrets/..2024_01_01_00_00_00/my-key  (actual data)
		// /secrets/..data -> ..2024_01_01_00_00_00
		// /secrets/my-key -> ..data/my-key
		dir := t.TempDir()
		dataDir := filepath.Join(dir, "..2024_01_01_00_00_00")
		require.NoError(t, os.Mkdir(dataDir, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(dataDir, "my-key"), []byte("secret-from-k8s"), 0600))

		require.NoError(t, os.Symlink("..2024_01_01_00_00_00", filepath.Join(dir, "..data")))
		require.NoError(t, os.Symlink("..data/my-key", filepath.Join(dir, "my-key")))

		val, err := ResolveFileKV(dir, "my-key")
		require.NoError(t, err)
		assert.Equal(t, "secret-from-k8s", val)
	})

	t.Run("picks up rotated k8s secret via symlink update", func(t *testing.T) {
		dir := t.TempDir()
		v1Dir := filepath.Join(dir, "..2024_01_01_00_00_00")
		require.NoError(t, os.Mkdir(v1Dir, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(v1Dir, "my-key"), []byte("old-secret"), 0600))
		require.NoError(t, os.Symlink("..2024_01_01_00_00_00", filepath.Join(dir, "..data")))
		require.NoError(t, os.Symlink("..data/my-key", filepath.Join(dir, "my-key")))

		val, err := ResolveFileKV(dir, "my-key")
		require.NoError(t, err)
		assert.Equal(t, "old-secret", val)

		// Simulate rotation: new version dir, atomic swap of ..data
		v2Dir := filepath.Join(dir, "..2024_06_01_00_00_00")
		require.NoError(t, os.Mkdir(v2Dir, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(v2Dir, "my-key"), []byte("new-secret"), 0600))
		require.NoError(t, os.Remove(filepath.Join(dir, "..data")))
		require.NoError(t, os.Symlink("..2024_06_01_00_00_00", filepath.Join(dir, "..data")))

		val, err = ResolveFileKV(dir, "my-key")
		require.NoError(t, err)
		assert.Equal(t, "new-secret", val)
	})
}

func TestConfined(t *testing.T) {
	cases := []struct {
		name   string
		base   string
		target string
		want   bool
	}{
		{"direct child", "/base", "/base/secret", true},
		{"nested child", "/base", "/base/sub/dir/secret", true},
		{"base itself", "/base", "/base", true},
		{"cleaned dotdot stays inside", "/base", "/base/sub/../secret", true},
		{"parent escape", "/base", "/base/../secret", false},
		{"sibling escape", "/base", "/other", false},
		{"prefix confusion is not confinement", "/base", "/base-evil", false},
		{"absolute outside", "/base", "/etc/passwd", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, confined(tc.base, tc.target))
		})
	}
}
