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
//
// If stripNewline is true, trailing \r\n and \n characters are removed from the result,
// which matches the typical behaviour of K8s secret mounts.
func ResolveFileKV(basePath, key string, stripNewline bool) (string, error) {
	path := key

	if basePath != "" {
		if filepath.IsAbs(key) {
			return "", fmt.Errorf("file KV: absolute path not allowed when base_path is set: %q", key)
		}

		joined := filepath.Join(basePath, key)
		// Ensure the cleaned path stays within basePath.
		rel, err := filepath.Rel(basePath, joined)
		if err != nil || strings.HasPrefix(rel, "..") {
			return "", fmt.Errorf("file KV: path traversal detected in key %q", key)
		}

		path = joined
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

	result := string(data)
	if stripNewline {
		result = strings.TrimRight(result, "\r\n")
	}

	return result, nil
}
