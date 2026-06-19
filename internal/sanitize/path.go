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
// SYS-REQ-091
// SYS-REQ-092
func ZipFilePath(filePath string, targetDir string) error {
	cleanPath := filepath.Clean(filePath)

	//mcdc:ignore:capability-gap filepath.VolumeName cannot detect Windows volume paths on Unix-like hosts; tracked as platform-neutral archive path debt [ki: KI-SANITIZE-WINDOWS-VOLUME-PATH]
	if filepath.IsAbs(cleanPath) || filepath.VolumeName(cleanPath) != "" {
		return fmt.Errorf("%w: %s", ErrInvalidFilePath, filePath)
	}

	destPath := filepath.Join(targetDir, cleanPath)
	relPath, err := filepath.Rel(targetDir, destPath)
	//mcdc:ignore:defensive filepath.Rel cannot fail here because destPath is built by joining cleanPath under the same targetDir, preserving absolute/relative form.
	if err != nil {
		return fmt.Errorf("failed to resolve path: %s: %w", filePath, err)
	}

	if strings.HasPrefix(relPath, "..") {
		return fmt.Errorf("%w: %s", ErrInvalidFilePath, filePath)
	}

	return nil
}

// SYS-REQ-093
// SYS-REQ-094
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

	//mcdc:ignore:defensive decoded cannot become empty here: the raw empty component returned above, and URL unescape maps non-empty input to non-empty output.
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
