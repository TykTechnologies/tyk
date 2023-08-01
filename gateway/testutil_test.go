package gateway

import (
	"runtime"
	"testing"
	"time"
)

func TestStartTestLeaks(t *testing.T) {
	t.Logf("Started with %d goroutines", runtime.NumGoroutine())

	ts := StartTest(nil)
	ts.Close()

	tick := func() {
		time.Sleep(time.Second)
		t.Logf("Tick with %d goroutines", runtime.NumGoroutine())
	}

	tick()
}
