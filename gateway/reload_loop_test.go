package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/test"
)

func TestReloadLoop_basic(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.ReloadTestCase.Enable()
	defer ts.Gw.ReloadTestCase.Disable()
	var n atomic.Value
	add := func() {
		if x := n.Load(); x != nil {
			n.Store(x.(int) + 1)
		} else {
			n.Store(int(0))
		}
	}

	ts.Gw.reloadURLStructure(add)
	ts.Gw.reloadURLStructure(add)
	ts.Gw.ReloadTestCase.TickOk(t)
	x := n.Load().(int)
	if x != 1 {
		t.Errorf("expected 1 got %d", x)
	}
}

func TestReloadLoop_handler(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.ReloadTestCase.Enable()
	defer ts.Gw.ReloadTestCase.Disable()
	var n atomic.Value
	add := func() {
		if x := n.Load(); x != nil {
			n.Store(x.(int) + 1)
		} else {
			n.Store(int(1))
		}
	}
	h := ts.Gw.resetHandler(add)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/reload", nil)
	h(w, r)
	ts.Gw.ReloadTestCase.TickOk(t)
	x := n.Load().(int)
	if x != 1 {
		t.Errorf("expected 1 got %d", x)
	}
}

func TestReloadLoop_handlerWithBlock(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.ReloadTestCase.Enable()
	defer ts.Gw.ReloadTestCase.Disable()

	signal := make(chan struct{}, 1)
	go func() {
		h := ts.Gw.resetHandler(nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/reload", nil)
		q := make(url.Values)
		q.Set("block", "true")
		r.URL.RawQuery = q.Encode()

		// we need to do this to make sure the goroutine has been scheduled before we
		// trigger a tick.
		signal <- struct{}{}
		h(w, r)
		signal <- struct{}{}
	}()
	<-signal
	ts.Gw.ReloadTestCase.TickOk(t)
	select {
	case <-signal:
	case <-time.After(10 * time.Millisecond):
		t.Fatal("Timedout on a blocking reload")
	}
}

func TestReloadLoop_group(t *testing.T) {
	test.Flaky(t) // TODO: TT-5252

	ts := StartTest(nil)
	defer ts.Close()

	res, err := http.Get(testReloadGroup)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Errorf("expected %d got %d", http.StatusOK, res.StatusCode)
	}

	ts.Gw.requeueLock.Lock()
	n := len(ts.Gw.requeue)
	ts.Gw.requeue = []func(){}
	ts.Gw.requeueLock.Unlock()
	if n != 1 {
		t.Errorf("expected 1 reload queue got %d", n)
	}
}
