package lifecycle_test

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/gateway"
)

func StartTest(t *testing.T, conf ...gateway.TestConfig) *gateway.Test {
	ts := gateway.StartTest(nil, conf...)
	t.Cleanup(ts.Close)
	return ts
}

func TestGateway_TestLifeCycle(t *testing.T) {
	var i int64
	go func() {
		for {
			go func() {
				t1 := gateway.StartTest(nil)
				t.Log(t1.URL)
				t1.Close()
			}()
			atomic.AddInt64(&i, 1)
		}
	}()

	// how to trigger shutdown
	// how to test shutdown
	time.Sleep(5 * time.Second)
	t.Logf("Got %d", atomic.LoadInt64(&i))
}
