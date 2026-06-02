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
		if err != nil || strings.HasPrefix(rel, "..") {
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

	data, err := os.ReadFile(resolved)
	if err != nil {
		return "", fmt.Errorf("file KV: cannot read file %q: %w", resolved, err)
	}

	// Secret files often have whitespaces
	result := strings.TrimSpace(string(data))

	return result, nil
}
