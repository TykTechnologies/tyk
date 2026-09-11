package osutil

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type Root struct {
	rootPath string
}

// NewRoot creates a Root scoped to the given directory path.
// This is the flexible and recommended way to create a scoped file system.
func NewRoot(path string) (*Root, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	// CRITICAL: Resolve physical path of the root directory.
	realRoot, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate root symlinks: %w", err)
	}

	info, err := os.Stat(realRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path '%s' is not a directory", realRoot)
	}

	return &Root{rootPath: realRoot}, nil
}

// Ensure that relative path is inside root directory.
// Methods detects escapes out of root directory.
func (r *Root) Ensure(target string) (string, error) {
	var fullPath string
	if filepath.IsAbs(target) {
		fullPath = filepath.Clean(target)
	} else {
		fullPath = filepath.Join(r.rootPath, target)
	}

	// Find the longest existing physical path prefix.
	existingPath := fullPath
	var uncreatedTail string

	for {
		realPath, err := filepath.EvalSymlinks(existingPath)
		if err == nil {
			// Reconstruct the physical path by appending non-existent components.
			if uncreatedTail != "" {
				fullPath = filepath.Join(realPath, uncreatedTail)
			} else {
				fullPath = realPath
			}
			break
		}

		if !os.IsNotExist(err) {
			return "", fmt.Errorf("path evaluation failed: %w", err)
		}

		// Strip the last component and loop to check the parent.
		base := filepath.Base(existingPath)
		if uncreatedTail == "" {
			uncreatedTail = base
		} else {
			uncreatedTail = filepath.Join(base, uncreatedTail)
		}

		parent := filepath.Dir(existingPath)
		if parent == existingPath {
			return "", fmt.Errorf("failed to resolve any existing parent directory")
		}
		existingPath = parent
	}

	rootWithSep := r.rootPath
	if !strings.HasSuffix(rootWithSep, string(os.PathSeparator)) {
		rootWithSep += string(os.PathSeparator)
	}

	if fullPath != r.rootPath && !strings.HasPrefix(fullPath, rootWithSep) {
		return "", fmt.Errorf("invalid path: '%s' attempts to escape root directory", target)
	}

	return fullPath, nil
}

// WriteFile writes data into file which locates inside of root directory.
func (r *Root) WriteFile(filePath string, data []byte, perm fs.FileMode) error {
	fullPath, err := r.Ensure(filePath)

	if err != nil {
		return err
	}

	return os.WriteFile(fullPath, data, perm)
}

// Remove file which is inside root path.
func (r *Root) Remove(filePath string) error {
	fullPath, err := r.Ensure(filePath)

	if err != nil {
		return err
	}

	return os.Remove(fullPath)
}

// Stat invokes os.Stat in safe scope
func (r *Root) Stat(filePath string) (os.FileInfo, error) {
	fullPath, err := r.Ensure(filePath)

	if err != nil {
		return nil, err
	}

	return os.Stat(fullPath)
}

// RootPath internal state getter.
func (r *Root) RootPath() string {
	return r.rootPath
}
