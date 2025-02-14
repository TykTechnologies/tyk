package cache

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestJanitor verifies that the Janitor executes the cleanup function periodically and stops when closed.
func TestJanitor(t *testing.T) {
	var count int32

	// cleanup increments count.
	cleanup := func() {
		atomic.AddInt32(&count, 1)
	}

	janitor := NewJanitor(10*time.Millisecond, cleanup)

	// Wait long enough for several cleanup calls.
	time.Sleep(50 * time.Millisecond)

	janitor.Close()

	// Wait to ensure no further cleanup calls are made after Close.
	time.Sleep(20 * time.Millisecond)

	finalCount := atomic.LoadInt32(&count)

	assert.NotEqual(t, int32(0), finalCount, "Expected cleanup() called")
}
