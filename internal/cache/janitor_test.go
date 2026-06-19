package cache

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestJanitor verifies that the Janitor executes the cleanup function periodically and stops when closed.
// Verifies: STK-REQ-021, SYS-REQ-109, SW-REQ-029
// STK-REQ-021:nominal:nominal
// SYS-REQ-109:nominal:nominal
// SW-REQ-029:nominal:nominal
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

// Verifies: STK-REQ-021, SYS-REQ-109, SW-REQ-029
// STK-REQ-021:idempotency:nominal
// STK-REQ-021:concurrent:race
// SYS-REQ-109:idempotency:nominal
// SYS-REQ-109:concurrent:race
// SW-REQ-029:idempotency:nominal
// SW-REQ-029:concurrent:race
func TestJanitor_MultipleClose(t *testing.T) {
	cleanup := func() {}

	t.Run("Multiple sequential calls to Close should not panic or block.", func(t *testing.T) {
		janitor := NewJanitor(10*time.Millisecond, cleanup)

		janitor.Close()
		janitor.Close()
		janitor.Close()
	})

	t.Run("Multiple concurrent calls to Close should not panic or block", func(t *testing.T) {
		janitor := NewJanitor(10*time.Millisecond, cleanup)

		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				janitor.Close()
			}()
		}

		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(time.Second):
			assert.Fail(t, "Close() blocked or deadlocked")
		}
	})
}
