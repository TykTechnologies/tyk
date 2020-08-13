package gateway

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestReloadLoop(t *testing.T) {
	var n atomic.Value
	add := func() {
		if x := n.Load(); x != nil {
			n.Store(x.(int) + 1)
		} else {
			n.Store(int(0))
		}
	}

	reloadURLStructure(add)
	reloadURLStructure(add)
	ReloadTick <- time.Time{}
	ReloadTick <- time.Time{} // This ensures all callbacks are executed.
	x := n.Load().(int)
	if x != 1 {
		t.Errorf("expected 1 got %d", x)
	}
}
