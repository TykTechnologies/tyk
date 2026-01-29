package sanitize

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

var ErrInvalidFilePath = errors.New("invalid file path in archive")

// ZipFilePath validates that a file path from a zip archive is safe and within the expected directory.
func ZipFilePath(filePath string, targetDir string) error {
	cleanPath := filepath.Clean(filePath)

	if filepath.IsAbs(cleanPath) || filepath.VolumeName(cleanPath) != "" {
		return fmt.Errorf("%w: %s", ErrInvalidFilePath, filePath)
	}

	destPath := filepath.Join(targetDir, cleanPath)
	relPath, err := filepath.Rel(targetDir, destPath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %s: %w", filePath, err)
	}

	if strings.HasPrefix(relPath, "..") {
		return fmt.Errorf("%w: %s", ErrInvalidFilePath, filePath)
	}

	return nil
}

// ValidatePathComponent validates that a string is a safe path component (filename)
// and does not contain path traversal sequences or separators.
func ValidatePathComponent(component string) error {
	// Reject empty, ".", and ".."
	if component == "" || component == "." || component == ".." {
		return fmt.Errorf("%w: invalid path component %q", ErrInvalidFilePath, component)
	}

	// The component must equal its base (no slashes or path separators)
	if filepath.Base(component) != component {
		return fmt.Errorf("%w: path component contains separators: %q", ErrInvalidFilePath, component)
	}

	// Additional check: ensure no path separators exist (handles URL encoding, etc.)
	if strings.ContainsAny(component, "/\\") {
		return fmt.Errorf("%w: path component contains separators: %q", ErrInvalidFilePath, component)
	}

	return nil
}
