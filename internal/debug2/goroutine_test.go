package debug2_test

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/debug2"
)

func TestNewRecordWithGoroutines(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	time.Sleep(100 * time.Millisecond)

	// Capture the initial state of goroutines
	initialRecord := debug2.NewRecord()

	// Create and start a new goroutine
	go func() {
		time.Sleep(100 * time.Millisecond)
	}()
	go func() {
		time.Sleep(100 * time.Millisecond)
	}()

	// Capture the state after starting the goroutine
	intermediateRecord := debug2.NewRecord()
	//	t.Log("The intermediate goroutines:\n", intermediateRecord.String())

	newGoroutines := intermediateRecord.Since(initialRecord)
	assert.Equal(t, 2, newGoroutines.Count(), "Expected new goroutines, but found none")

	for {
		// Wait for the goroutine to finish
		time.Sleep(100 * time.Millisecond)
		runtime.GC()
		time.Sleep(10 * time.Millisecond)

		// Capture the state after the goroutine has finished
		finalRecord := debug2.NewRecord()
		remainingGoroutines := finalRecord.Since(initialRecord)

		// Expecting goroutines clear
		if remainingGoroutines.Count() == 0 {
			break
		}

		if ctx.Err() != nil {
			break
		}

		fmt.Print(remainingGoroutines.String())
	}

	assert.NoError(t, ctx.Err(), "cancelled goroutine leak check after timeout")
}

func BenchmarkNewRecordWithGoroutines(b *testing.B) {
	// Capture the initial state of goroutines
	initialRecord := debug2.NewRecord()

	// Create and start a new goroutine

	var wg sync.WaitGroup
	wg.Add(b.N)

	var i int
	for i = 0; i < b.N; i++ {
		go func() {
			defer wg.Done()

			time.Sleep(100 * time.Millisecond)
		}()
	}

	// Capture the state after starting the goroutine
	intermediateRecord := debug2.NewRecord()
	b.Logf("Started %d goroutines with sleep", b.N)
	b.Log("Intermediate Record count: ", intermediateRecord.Count())

	wg.Wait()

	runtime.GC()

	// Capture the state after the goroutine has finished
	finalRecord := debug2.NewRecord()
	b.Log("Finished with finalRecord count: ", finalRecord.Count())

	// Check that the intermediate record contains the new goroutine
	newGoroutines := intermediateRecord.Since(initialRecord)
	assert.Greater(b, newGoroutines.Count(), 0, "Expected new goroutines, but found none")

	// Check that the final record no longer contains the new goroutine
	remainingGoroutines := finalRecord.Since(initialRecord)
	assert.Equal(b, 0, remainingGoroutines.Count(), "Expected no new goroutines, but found: "+remainingGoroutines.String())
}
