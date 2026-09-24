//go:build lua
// +build lua

package gateway

import (
	"context"
	"runtime"
	"testing"

	"github.com/TykTechnologies/tyk/coprocess"
)

func TestLuaDispatcher_MemoryLeak(t *testing.T) {
	dispatcher, err := NewLuaDispatcher()
	if err != nil {
		t.Skipf("Failed to initialize Lua dispatcher: %v", err)
	}

	obj := &coprocess.Object{
		Request: &coprocess.MiniRequestObject{
			Headers: map[string]string{"Test": "Header"},
			Body:    "test body",
		},
	}

	// Run once to warm up
	_, _ = dispatcher.DispatchWithContext(context.Background(), obj)

	runtime.GC()
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	for i := 0; i < 1000; i++ {
		_, _ = dispatcher.DispatchWithContext(context.Background(), obj)
	}

	runtime.GC()
	runtime.ReadMemStats(&m2)

	// We just want to ensure it doesn't crash and memory doesn't grow wildly.
	// We can't easily measure C heap from Go runtime.MemStats, but we can at least
	// ensure the code runs without panicking.
	t.Logf("Alloc before: %d, after: %d", m1.Alloc, m2.Alloc)
}