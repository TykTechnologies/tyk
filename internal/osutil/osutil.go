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
		return nil, fmt.Errorf("failed to get absolute path for '%s': %w", path, err)
	}

	info, err := os.Stat(absPath)

	if err != nil {
		return nil, fmt.Errorf("failed to stat path '%s': %w", absPath, err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("path '%s' is not a directory", absPath)
	}

	return &Root{
		rootPath: absPath,
	}, nil
}

// Ensure that relative path is inside root directory.
// Methods detects escapes out of root directory.
func (r *Root) Ensure(relative string) (string, error) {
	fullPath := filepath.Join(r.rootPath, relative)

	rootWithSep := r.rootPath
	if !strings.HasSuffix(rootWithSep, string(os.PathSeparator)) {
		rootWithSep += string(os.PathSeparator)
	}

	if fullPath != r.rootPath && !strings.HasPrefix(fullPath, rootWithSep) {
		return "", fmt.Errorf("invalid path: '%s' attempts to escape root directory", relative)
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
