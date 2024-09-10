package test

import (
	"os"
	"sync"
	"testing"
)

var (
	// exclusiveTestMu is used by Exclusive()
	exclusiveTestMu sync.Mutex
)

// CI returns true when a non-empty CI env is present
func CI() bool {
	return os.Getenv("CI") != ""
}

// Flaky skips a flaky test in a CI environment
func Flaky(t *testing.T, fake ...func() (bool, func(...interface{}))) {
	skipCI(t, "Skipping flaky test", fake...)
}

// Racy skips a racy test in a CI environment
func Racy(t *testing.T, fake ...func() (bool, func(...interface{}))) {
	skipCI(t, "Skipping Racy test", fake...)
}

// Exclusive uses a lock to gate only a single test running.
func Exclusive(t *testing.T) {
	t.Log("# Test marked as exclusive")
	exclusiveTestMu.Lock()
	t.Cleanup(func() {
		exclusiveTestMu.Unlock()
	})
}

func skipCI(t *testing.T, message string, fake ...func() (bool, func(...interface{}))) {
	var (
		ci   = CI()
		skip = t.Skip
	)
	if len(fake) > 0 {
		ci, skip = fake[0]()
	}
	if ci {
		skip(message)
	} else {
		t.Log("# Skip this flaky/racy test by setting env CI=true")
	}
}
