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
