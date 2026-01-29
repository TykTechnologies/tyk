package sanitize

import (
	"errors"
	"fmt"
	"net/url"
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

func ValidatePathComponent(component string) error {
	if component == "" || component == "." || component == ".." {
		return fmt.Errorf("%w: invalid path component %q", ErrInvalidFilePath, component)
	}

	decoded := component
	for i := 0; i < 3; i++ {
		newDecoded, err := url.QueryUnescape(decoded)
		if err != nil {
			break
		}
		if newDecoded == decoded {
			break
		}
		decoded = newDecoded
	}

	if decoded == "" || decoded == "." || decoded == ".." {
		return fmt.Errorf("%w: invalid path component %q", ErrInvalidFilePath, component)
	}

	if filepath.Base(decoded) != decoded {
		return fmt.Errorf("%w: path component contains separators: %q", ErrInvalidFilePath, component)
	}

	if strings.ContainsAny(decoded, "/\\") {
		return fmt.Errorf("%w: path component contains separators: %q", ErrInvalidFilePath, component)
	}

	return nil
}
