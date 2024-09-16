package plugin

import (
	"os"
	"path/filepath"
)

// realpath returns the canonicalized absolute pathname.
func realpath(path string) (string, error) {
	if len(path) == 0 {
		return "", os.ErrInvalid
	}

	var err error

	if !filepath.IsAbs(path) {
		path, err = filepath.Abs(path)
		if err != nil {
			return "", err
		}
	}

	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}

	// symbolic link?
	if fi.Mode()&os.ModeSymlink != 0 {
		path, err = os.Readlink(path)
		if err != nil {
			return "", err
		}

		return path, nil
	}

	return filepath.Clean(path), nil
}
