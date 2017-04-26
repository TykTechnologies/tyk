package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestJSVMProcessTimeout(t *testing.T) {
	dynMid := &DynamicMiddleware{
		TykMiddleware: &TykMiddleware{
			Spec: &APISpec{},
		},
		MiddlewareClassName: "leakMid",
		Pre:                 true,
	}
	req := httptest.NewRequest("GET", "/foo", strings.NewReader("body"))
	jsvm := &JSVM{}
	jsvm.Init()

	// this js plugin just loops forever, keeping Otto at 100% CPU
	// usage and running forever.
	const js = `
var leakMid = new TykJS.TykMiddleware.NewMiddleware({});

leakMid.NewProcessRequest(function(request, session) {
       while (true) {
       }
       return leakMid.ReturnData(request, session.meta_data);
});
`
	if _, err := jsvm.VM.Run(js); err != nil {
		t.Fatalf("failed to set up js plugin: %v", err)
	}
	dynMid.Spec.JSVM = jsvm

	done := make(chan bool)
	go func() {
		dynMid.ProcessRequest(nil, req, nil)
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("js vm wasn't killed after its timeout")
	}
}
