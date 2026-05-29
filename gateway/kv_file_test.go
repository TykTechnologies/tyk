package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKVStoreFileScheme tests that kvStore() resolves file:// URIs.
func TestKVStoreFileScheme(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("resolves file:// to file contents", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "secret")
		require.NoError(t, os.WriteFile(f, []byte("super-secret\n"), 0600))

		val, err := ts.Gw.kvStore("file://" + f)
		require.NoError(t, err)
		assert.Equal(t, "super-secret", val)
	})

	t.Run("returns error for missing file", func(t *testing.T) {
		_, err := ts.Gw.kvStore("file:///nonexistent/file")
		assert.Error(t, err)
	})

	t.Run("passes through non-file values unchanged", func(t *testing.T) {
		val, err := ts.Gw.kvStore("plain-string")
		require.NoError(t, err)
		assert.Equal(t, "plain-string", val)
	})
}

func TestResolveFileKV(t *testing.T) {
	t.Run("reads plain file contents", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "secret.txt")
		require.NoError(t, os.WriteFile(f, []byte("my-secret-value"), 0600))

		val, err := ResolveFileKV("", f, false)
		require.NoError(t, err)
		assert.Equal(t, "my-secret-value", val)
	})

	t.Run("strips trailing newline by default", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "secret.txt")
		require.NoError(t, os.WriteFile(f, []byte("my-secret-value\n"), 0600))

		val, err := ResolveFileKV("", f, true)
		require.NoError(t, err)
		assert.Equal(t, "my-secret-value", val)
	})

	t.Run("strips trailing newline CRLF", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "secret.txt")
		require.NoError(t, os.WriteFile(f, []byte("my-secret-value\r\n"), 0600))

		val, err := ResolveFileKV("", f, true)
		require.NoError(t, err)
		assert.Equal(t, "my-secret-value", val)
	})

	t.Run("preserves multi-line content except trailing newline", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "cert.pem")
		pem := "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJ\n-----END CERTIFICATE-----\n"
		require.NoError(t, os.WriteFile(f, []byte(pem), 0600))

		val, err := ResolveFileKV("", f, true)
		require.NoError(t, err)
		assert.Equal(t, "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJ\n-----END CERTIFICATE-----", val)
	})

	t.Run("returns error for non-existent file", func(t *testing.T) {
		_, err := ResolveFileKV("", "/nonexistent/path/secret.txt", false)
		assert.Error(t, err)
	})

	t.Run("resolves key relative to basePath", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "api-key")
		require.NoError(t, os.WriteFile(f, []byte("the-api-key"), 0600))

		val, err := ResolveFileKV(dir, "api-key", true)
		require.NoError(t, err)
		assert.Equal(t, "the-api-key", val)
	})

	t.Run("rejects absolute path when basePath is set", func(t *testing.T) {
		dir := t.TempDir()
		_, err := ResolveFileKV(dir, "/etc/passwd", false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "absolute")
	})

	t.Run("rejects dotdot traversal when basePath is set", func(t *testing.T) {
		dir := t.TempDir()
		_, err := ResolveFileKV(dir, "../etc/passwd", false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "traversal")
	})

	t.Run("rejects embedded dotdot traversal", func(t *testing.T) {
		dir := t.TempDir()
		_, err := ResolveFileKV(dir, "subdir/../../etc/passwd", false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "traversal")
	})

	t.Run("allows absolute path when basePath is empty", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "secret")
		require.NoError(t, os.WriteFile(f, []byte("value"), 0600))

		val, err := ResolveFileKV("", f, true)
		require.NoError(t, err)
		assert.Equal(t, "value", val)
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

		// Create ..data symlink pointing to the timestamped dir
		require.NoError(t, os.Symlink("..2024_01_01_00_00_00", filepath.Join(dir, "..data")))
		// Create my-key symlink pointing through ..data
		require.NoError(t, os.Symlink("..data/my-key", filepath.Join(dir, "my-key")))

		val, err := ResolveFileKV(dir, "my-key", true)
		require.NoError(t, err)
		assert.Equal(t, "secret-from-k8s", val)
	})

	t.Run("picks up rotated k8s secret via symlink update", func(t *testing.T) {
		// Initial mount
		dir := t.TempDir()
		v1Dir := filepath.Join(dir, "..2024_01_01_00_00_00")
		require.NoError(t, os.Mkdir(v1Dir, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(v1Dir, "my-key"), []byte("old-secret"), 0600))
		require.NoError(t, os.Symlink("..2024_01_01_00_00_00", filepath.Join(dir, "..data")))
		require.NoError(t, os.Symlink("..data/my-key", filepath.Join(dir, "my-key")))

		val, err := ResolveFileKV(dir, "my-key", true)
		require.NoError(t, err)
		assert.Equal(t, "old-secret", val)

		// Simulate rotation: new version dir, atomic swap of ..data
		v2Dir := filepath.Join(dir, "..2024_06_01_00_00_00")
		require.NoError(t, os.Mkdir(v2Dir, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(v2Dir, "my-key"), []byte("new-secret"), 0600))
		require.NoError(t, os.Remove(filepath.Join(dir, "..data")))
		require.NoError(t, os.Symlink("..2024_06_01_00_00_00", filepath.Join(dir, "..data")))

		val, err = ResolveFileKV(dir, "my-key", true)
		require.NoError(t, err)
		assert.Equal(t, "new-secret", val)
	})
}
