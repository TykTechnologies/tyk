package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveFileKV reads the contents of a file at the given key path and returns it as a string.
// When basePath is empty the key is used directly as a file path, with no restrictions.
func ResolveFileKV(basePath, key string) (string, error) {
	path := key

	switch {
	case filepath.IsAbs(key):
		path = key
	case basePath != "":
		joined := filepath.Join(basePath, key)
		rel, err := filepath.Rel(basePath, joined)
		if err != nil || !filepath.IsLocal(rel) {
			return "", fmt.Errorf("file KV: path traversal detected in key %q", key)
		}
		path = joined
	default:
		return "", fmt.Errorf(
			"file KV: key %q is a relative path but kv.file.base_path is not configured; "+
				"set kv.file.base_path or use an absolute path",
			key,
		)
	}

	// Resolve K8s AtomicWriter symlinks (e.g. ..data -> ..2024_01_01_00_00_00).
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("file KV: cannot resolve path %q: %w", path, err)
	}

	// Re-verify after symlink resolution: a symlink inside basePath can point
	// outside (symlink escape).
	if basePath != "" && !filepath.IsAbs(key) {
		canonicalBase, err := filepath.EvalSymlinks(basePath)
		if err != nil {
			canonicalBase = basePath
		}
		rel, err := filepath.Rel(canonicalBase, resolved)
		if err != nil || !filepath.IsLocal(rel) {
			return "", fmt.Errorf("file KV: symlink escape detected for key %q: resolved to %q which is outside base_path", key, resolved)
		}
	}

	data, err := os.ReadFile(resolved)
	if err != nil {
		return "", fmt.Errorf("file KV: cannot read file %q: %w", resolved, err)
	}

	return strings.TrimRight(string(data), "\r\n"), nil
}
