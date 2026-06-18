package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveFileKV reads the file at key and returns its contents trimmed of trailing newlines.
//
// basePath is a mandatory security boundary: file:// references resolve only when
// it is configured. Keys must be relative; they are joined to basePath and confined
// within it, so untrusted input cannot escape the boundary to read arbitrary files.
// Absolute keys are rejected.
//
// When basePath is empty no boundary is configured, so every key is rejected.
func ResolveFileKV(basePath, key string) (string, error) {
	path, err := resolveKeyPath(basePath, key)
	if err != nil {
		return "", err
	}

	// Resolve K8s AtomicWriter symlinks (e.g. ..data -> ..2024_01_01_00_00_00).
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("file KV: cannot resolve path %q: %w", path, err)
	}

	// Re-verify after symlink resolution: a symlink inside basePath can point
	// outside (symlink escape).
	canonicalBase, err := filepath.EvalSymlinks(basePath)
	// EvalSymlinks failure here requires a race (basePath symlink broken between
	// resolving the file path above and this call). Not worth a flaky test.
	if err != nil {
		return "", fmt.Errorf("file KV: cannot resolve base_path %q: %w", basePath, err)
	}

	if !confined(canonicalBase, resolved) {
		return "", fmt.Errorf(
			"file KV: symlink escape detected for key %q: resolved to %q which is outside base_path",
			key,
			resolved,
		)
	}

	data, err := os.ReadFile(resolved)
	if err != nil {
		return "", fmt.Errorf("file KV: cannot read file %q: %w", resolved, err)
	}

	return strings.TrimRight(string(data), "\r\n"), nil
}

// resolveKeyPath applies the base_path boundary policy and returns the
// candidate file path.
func resolveKeyPath(basePath, key string) (string, error) {
	if basePath == "" {
		return "", fmt.Errorf(
			"file KV: cannot resolve key %q because kv.file.base_path is not configured; "+
				"set kv.file.base_path to enable file:// references",
			key,
		)
	}

	// A relative base_path resolves against the process working directory, which
	// is non-deterministic across deployments and defeats the purpose of a fixed
	// boundary.
	if !filepath.IsAbs(basePath) {
		return "", fmt.Errorf(
			"file KV: kv.file.base_path %q must be an absolute path",
			basePath,
		)
	}

	if key == "" {
		return "", fmt.Errorf("file KV: file:// reference has an empty key; specify a path relative to base_path")
	}

	if filepath.IsAbs(key) {
		return "", fmt.Errorf(
			"file KV: absolute path %q rejected because kv.file.base_path is configured; "+
				"use a path relative to base_path",
			key,
		)
	}

	joined := filepath.Join(basePath, key)
	if !confined(basePath, joined) {
		return "", fmt.Errorf("file KV: path traversal detected in key %q", key)
	}

	return joined, nil
}

// confined reports whether target resolves to a location within base,
// using lexical analysis only.
func confined(base, target string) bool {
	rel, err := filepath.Rel(base, target)
	return err == nil && filepath.IsLocal(rel)
}
