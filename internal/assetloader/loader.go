// Package assetloader loads files that API definitions reference on the
// gateway host, confining them to a configured root directory.
package assetloader

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TykTechnologies/tyk/pkg/osutil"
)

// ErrPathRejected marks a path that resolves outside the root. The wrapped
// osutil error names the offending path, so callers that must not disclose
// it match on this sentinel instead of logging the error.
var ErrPathRejected = errors.New("asset path rejected")

// Loader resolves and reads files under a root directory.
type Loader struct {
	root                  *osutil.Root
	initErr               error
	allowUnsafe           bool
	legacyWorkingDirPaths bool

	// rootInWorkingDir is the root's path relative to the working directory,
	// with a trailing separator, when the root is a subdirectory of it
	// (templates/ for the default layout). Empty otherwise.
	rootInWorkingDir string
}

type Option func(*Loader)

// WithAllowUnsafe makes the Loader use paths verbatim, without confinement,
// restoring the historical unconfined behaviour.
func WithAllowUnsafe(allow bool) Option {
	return func(l *Loader) { l.allowUnsafe = allow }
}

// WithLegacyWorkingDirPaths controls whether relative paths written relative
// to the working directory are accepted, as they were read before confinement
// and as the docs still write them (./templates/x.tmpl, middleware/sample.js).
// Enabled by default. In the default layout the root is a subdirectory of the
// working directory, so such a path is the root-relative path with the root's
// own name in front; that prefix is stripped before resolution. In any other
// layout the form cannot land inside the root and nothing is stripped.
func WithLegacyWorkingDirPaths(enabled bool) Option {
	return func(l *Loader) { l.legacyWorkingDirPaths = enabled }
}

// New builds a Loader rooted at rootPath. When the root cannot be opened the
// error is returned alongside a Loader that fails closed, so the caller can
// log the cause once and keep running.
func New(rootPath string, opts ...Option) (*Loader, error) {
	l := &Loader{legacyWorkingDirPaths: true}
	for _, opt := range opts {
		opt(l)
	}

	root, err := osutil.NewRoot(rootPath)
	if err != nil {
		l.initErr = fmt.Errorf("asset root %q is not available: %w", rootPath, err)
		if l.allowUnsafe {
			return l, nil
		}
		return l, l.initErr
	}

	l.root = root
	if l.legacyWorkingDirPaths {
		l.rootInWorkingDir = rootInWorkingDir(root.RootPath())
	}

	return l, nil
}

// rootInWorkingDir returns root relative to the working directory with a
// trailing separator when root lies strictly inside it, and "" otherwise.
// The working directory does not change while the gateway runs, so this is
// computed once.
func rootInWorkingDir(root string) string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}

	if realWd, err := filepath.EvalSymlinks(wd); err == nil {
		wd = realWd
	}

	rel, err := filepath.Rel(wd, root)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ""
	}

	return rel + string(filepath.Separator)
}

// ResolvePath returns the path the gateway will read, confined to the root via
// osutil.Root, which also resolves symlinks and relative segments. Relative
// paths are taken relative to the root, see WithLegacyWorkingDirPaths.
func (l *Loader) ResolvePath(path string) (string, error) {
	if l.allowUnsafe {
		return path, nil
	}

	if l.initErr != nil {
		return "", l.initErr
	}

	resolved, err := l.root.Ensure(strings.TrimPrefix(filepath.Clean(path), l.rootInWorkingDir))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrPathRejected, err)
	}

	return resolved, nil
}

// Load resolves path and reads the file behind it.
func (l *Loader) Load(path string) ([]byte, error) {
	resolved, err := l.ResolvePath(path)
	if err != nil {
		return nil, err
	}

	return os.ReadFile(resolved)
}
