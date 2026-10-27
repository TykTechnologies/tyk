package assetloader

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newLayout creates <base>/root as the confined directory and <base>/outside with
// a file the loader must never reach, plus a symlink inside the root pointing at it.
func newLayout(t *testing.T) (base, root, outside string) {
	t.Helper()

	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)

	root = filepath.Join(base, "root")
	outside = filepath.Join(base, "outside")
	require.NoError(t, os.MkdirAll(root, 0o755))
	require.NoError(t, os.MkdirAll(outside, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "asset.js"), []byte("ok"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret.js"), []byte("secret"), 0o644))
	require.NoError(t, os.Symlink(filepath.Join(outside, "secret.js"), filepath.Join(root, "escape.js")))

	return base, root, outside
}

func mustNew(t *testing.T, root string, opts ...Option) *Loader {
	t.Helper()

	l, err := New(root, opts...)
	require.NoError(t, err)
	return l
}

func TestLoader_Resolve(t *testing.T) {
	base, root, outside := newLayout(t)

	t.Run("unsafe flag returns the path verbatim", func(t *testing.T) {
		l := mustNew(t, root, WithAllowUnsafe(true))

		for _, path := range []string{"../outside/secret.js", "/etc/passwd", "escape.js"} {
			got, err := l.ResolvePath(path)

			assert.NoError(t, err)
			assert.Equal(t, path, got)
		}
	})

	t.Run("rejects traversal and absolute paths outside the root", func(t *testing.T) {
		l := mustNew(t, root)

		for _, path := range []string{"../outside/secret.js", filepath.Join(outside, "secret.js"), "/etc/passwd", "../../../../../../etc/passwd"} {
			got, err := l.ResolvePath(path)

			assert.ErrorIs(t, err, ErrPathRejected, "path %q", path)
			assert.ErrorContains(t, err, "attempts to escape root directory", "path %q", path)
			assert.Empty(t, got)
		}
	})

	t.Run("rejects a symlink escaping the root", func(t *testing.T) {
		l := mustNew(t, root)

		for _, path := range []string{"escape.js", filepath.Join(root, "escape.js")} {
			got, err := l.ResolvePath(path)

			assert.ErrorIs(t, err, ErrPathRejected, "path %q", path)
			assert.Empty(t, got)
		}
	})

	t.Run("resolves paths inside the root", func(t *testing.T) {
		l := mustNew(t, root)

		for _, path := range []string{"asset.js", filepath.Join(root, "asset.js"), "nested/../asset.js", "missing.js"} {
			got, err := l.ResolvePath(path)

			assert.NoError(t, err, "path %q", path)
			assert.Equal(t, filepath.Join(root, filepath.Base(path)), got)
		}
	})

	t.Run("root inside the working directory: strips the root prefix", func(t *testing.T) {
		// Default layout and the documented form: cwd/root/asset.js written as root/asset.js.
		t.Chdir(base)
		l := mustNew(t, root)

		for _, path := range []string{"./root/asset.js", "root/asset.js", "root/nested/../asset.js"} {
			got, err := l.ResolvePath(path)

			assert.NoError(t, err, "path %q", path)
			assert.Equal(t, filepath.Join(root, "asset.js"), got)
		}
	})

	t.Run("root inside the working directory: plain names stay root-relative", func(t *testing.T) {
		// A same-named file in the working directory, outside the root, is ignored.
		require.NoError(t, os.WriteFile(filepath.Join(base, "asset.js"), []byte("outside"), 0o644))
		t.Chdir(base)
		l := mustNew(t, root)

		got, err := l.ResolvePath("asset.js")

		assert.NoError(t, err)
		assert.Equal(t, filepath.Join(root, "asset.js"), got)
	})

	t.Run("root inside the working directory: sibling paths resolve under the root", func(t *testing.T) {
		// cwd/outside/secret.js exists but is never reached: the path is root-relative.
		t.Chdir(base)
		l := mustNew(t, root)

		got, err := l.ResolvePath("outside/secret.js")

		assert.NoError(t, err)
		assert.Equal(t, filepath.Join(root, "outside", "secret.js"), got)
	})

	t.Run("root inside the working directory: prefix kept when legacy paths are off", func(t *testing.T) {
		t.Chdir(base)
		l := mustNew(t, root, WithLegacyWorkingDirPaths(false))

		got, err := l.ResolvePath("root/asset.js")

		assert.NoError(t, err)
		assert.Equal(t, filepath.Join(root, "root", "asset.js"), got)
	})

	t.Run("working directory equals the root", func(t *testing.T) {
		t.Chdir(root)
		l := mustNew(t, root)

		got, err := l.ResolvePath("asset.js")

		assert.NoError(t, err)
		assert.Equal(t, filepath.Join(root, "asset.js"), got)
	})

	t.Run("working directory inside the root", func(t *testing.T) {
		nested := filepath.Join(root, "nested")
		require.NoError(t, os.MkdirAll(nested, 0o755))
		t.Chdir(nested)
		l := mustNew(t, root)

		got, err := l.ResolvePath("asset.js")

		assert.NoError(t, err)
		assert.Equal(t, filepath.Join(root, "asset.js"), got)
	})

	t.Run("working directory unrelated to the root", func(t *testing.T) {
		t.Chdir(outside)
		l := mustNew(t, root)

		got, err := l.ResolvePath("root/asset.js")

		assert.NoError(t, err)
		assert.Equal(t, filepath.Join(root, "root", "asset.js"), got)
	})
}

func TestNew_MissingRoot(t *testing.T) {
	base, _, _ := newLayout(t)
	missing := filepath.Join(base, "missing")

	t.Run("reports the cause and fails closed", func(t *testing.T) {
		l, err := New(missing)

		require.Error(t, err)
		require.NotNil(t, l)

		got, resolveErr := l.ResolvePath("asset.js")

		assert.Equal(t, err, resolveErr)
		assert.Empty(t, got)
	})

	t.Run("unsafe flag does not need the root", func(t *testing.T) {
		l, err := New(missing, WithAllowUnsafe(true))

		require.NoError(t, err)

		got, err := l.ResolvePath("/etc/passwd")

		assert.NoError(t, err)
		assert.Equal(t, "/etc/passwd", got)
	})
}

func TestLoader_Load(t *testing.T) {
	base, root, outside := newLayout(t)

	t.Run("reads a file inside the root", func(t *testing.T) {
		l := mustNew(t, root)

		data, err := l.Load("asset.js")

		assert.NoError(t, err)
		assert.Equal(t, "ok", string(data))
	})

	t.Run("rejects a file outside the root", func(t *testing.T) {
		l := mustNew(t, root)

		for _, path := range []string{"../outside/secret.js", filepath.Join(outside, "secret.js"), "escape.js"} {
			data, err := l.Load(path)

			assert.ErrorIs(t, err, ErrPathRejected, "path %q", path)
			assert.Nil(t, data)
		}
	})

	t.Run("reports a missing file as a read error", func(t *testing.T) {
		l := mustNew(t, root)

		data, err := l.Load("missing.js")

		assert.ErrorIs(t, err, os.ErrNotExist)
		assert.NotErrorIs(t, err, ErrPathRejected)
		assert.Nil(t, data)
	})

	t.Run("unsafe flag reads any file", func(t *testing.T) {
		l := mustNew(t, root, WithAllowUnsafe(true))

		data, err := l.Load(filepath.Join(base, "outside", "secret.js"))

		assert.NoError(t, err)
		assert.Equal(t, "secret", string(data))
	})
}
