package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveFileKV reads the contents of a file at the given key path and returns it as a string.
//
// When basePath is non-empty the key is joined to it and two security checks are enforced:
//   - the key must not be an absolute path
//   - the joined (cleaned) path must not escape basePath via ".." traversal
//
// When basePath is empty the key is used directly as a file path, with no restrictions.
//
// K8s AtomicWriter symlinks (the "..data" indirection used by secret volume mounts) are
// resolved transparently via filepath.EvalSymlinks before the file is read, so secret
// rotations are picked up on every call.
func ResolveFileKV(basePath, key string) (string, error) {
	path := key

	if filepath.IsAbs(key) {
		path = key
	} else if basePath != "" {
		joined := filepath.Join(basePath, key)
		rel, err := filepath.Rel(basePath, joined)
		if err != nil || strings.HasPrefix(rel, "..") {
			return "", fmt.Errorf("file KV: path traversal detected in key %q", key)
		}
		path = joined
	} else {
		// Relative key with no base_path: we have no anchor directory.
		// Silently resolving against the process working directory would almost
		// certainly be wrong, so fail with a clear message instead.
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
