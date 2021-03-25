package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestReloadLoop_basic(t *testing.T) {
	ReloadTestCase.Enable()
	defer ReloadTestCase.Disable()
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
	ReloadTestCase.TickOk(t)
	x := n.Load().(int)
	if x != 1 {
		t.Errorf("expected 1 got %d", x)
	}
}

func TestReloadLoop_handler(t *testing.T) {
	ReloadTestCase.Enable()
	defer ReloadTestCase.Disable()
	var n atomic.Value
	add := func() {
		if x := n.Load(); x != nil {
			n.Store(x.(int) + 1)
		} else {
			n.Store(int(1))
		}
	}
	h := resetHandler(add)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/reload", nil)
	h(w, r)
	ReloadTestCase.TickOk(t)
	x := n.Load().(int)
	if x != 1 {
		t.Errorf("expected 1 got %d", x)
	}
}

func TestReloadLoop_handlerWithBlock(t *testing.T) {
	ReloadTestCase.Enable()
	defer ReloadTestCase.Disable()

	signal := make(chan struct{}, 1)
	go func() {
		h := resetHandler(nil)
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
	ReloadTestCase.TickOk(t)
	select {
	case <-signal:
	case <-time.After(10 * time.Millisecond):
		t.Fatal("Timedout on a blocking reload")
	}
}

func TestReloadLoop_group(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	res, err := http.Get(testReloadGroup)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Errorf("expected %d got %d", http.StatusOK, res.StatusCode)
	}
	time.Sleep(time.Second)
	requeueLock.Lock()
	n := len(requeue)
	requeue = []func(){}
	requeueLock.Unlock()
	if n != 1 {
		t.Errorf("expected 1 reload queue got %d", n)
	}
}
