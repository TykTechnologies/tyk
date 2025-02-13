package lifecycle_test

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shirou/gopsutil/mem"

	"github.com/TykTechnologies/tyk/gateway"
)

func StartTest(t *testing.T, conf ...gateway.TestConfig) *gateway.Test {
	ts := gateway.StartTest(nil, conf...)
	t.Cleanup(ts.Close)
	return ts
}

// The test starts and stops an unbonded amount of gateways, which
// is a terrible idea for system resources and GC churn.
//
// Because of this, a naive context timeout tries to limit how long it runs.
func TestGateway_TestLifeCycle(t *testing.T) {
	if ok, _ := strconv.ParseBool(os.Getenv("TEST_LIFECYCLE")); !ok {
		t.Skipf("Enable test with TEST_LIFECYCLE=1 (or 'true')")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	var i int64

	func() {
		for {
			// Run runtime.GC every 16 (0xF) loops.
			current := atomic.LoadInt64(&i)
			if (current & 0xff) == 0 {
				if err := printMemStats(t); err != nil {
					t.Logf("Breaking out on error: %v", err)
					break
				}
				runtime.GC()
			}

			go func() {
				t1 := gateway.StartTest(nil)
				t.Log(t1.URL)
				t1.Close()
			}()
			atomic.AddInt64(&i, 1)

			select {
			case <-ctx.Done():
				return
			default:
			}

		}
	}()

	t.Logf("Got %d gateway Start/Stop's", atomic.LoadInt64(&i))
}

func printMemStats(tb testing.TB) error {
	// Retrieve process memory stats.
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Retrieve system memory info.
	vm, err := mem.VirtualMemory()
	if err != nil {
		return err
	}

	tb.Logf("Process allocated memory: %d bytes, System memory used: %.2f%%", m.Alloc, vm.UsedPercent)

	// If system memory usage exceeds 90%, break out of the test.
	if vm.UsedPercent > 90.0 {
		return errors.New("Exceeded memory treshold.")
	}

	return nil
}
