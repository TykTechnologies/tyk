package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TykTechnologies/tykcommon"
)

func TestJSVMProcessTimeout(t *testing.T) {
	dynMid := &DynamicMiddleware{
		TykMiddleware: &TykMiddleware{
			Spec: &APISpec{APIDefinition: &tykcommon.APIDefinition{}},
		},
		MiddlewareClassName: "leakMid",
		Pre:                 true,
	}
	req := httptest.NewRequest("GET", "/foo", strings.NewReader("body"))
	jsvm := &JSVM{}
	jsvm.Init()
	jsvm.Timeout = time.Millisecond

	// this js plugin just loops forever, keeping Otto at 100% CPU
	// usage and running forever.
	const js = `
var leakMid = new TykJS.TykMiddleware.NewMiddleware({});

leakMid.NewProcessRequest(function(request, session) {
	while (true) {
	}
	return leakMid.ReturnData(request, session.meta_data);
});`
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

func TestJSVMConfigData(t *testing.T) {
	spec := &APISpec{APIDefinition: &tykcommon.APIDefinition{}}
	spec.RawData = map[string]interface{}{
		"config_data": map[string]interface{}{
			"foo": "x",
			"bar": map[string]interface{}{"y": 3},
		},
	}
	const js = `
var testJSVMData = new TykJS.TykMiddleware.NewMiddleware({});

testJSVMData.NewProcessRequest(function(request, session, config) {
	request.SetHeaders["data-foo"] = config.config_data.foo;
	request.SetHeaders["data-bar-y"] = config.config_data.bar.y.toString();
	return testJSVMData.ReturnData(request, {});
});`
	dynMid := &DynamicMiddleware{
		TykMiddleware:       &TykMiddleware{spec, nil},
		MiddlewareClassName: "testJSVMData",
		Pre:                 true,
	}
	jsvm := &JSVM{}
	jsvm.Init()
	if _, err := jsvm.VM.Run(js); err != nil {
		t.Fatalf("failed to set up js plugin: %v", err)
	}
	dynMid.Spec.JSVM = jsvm

	r := httptest.NewRequest("GET", "/v1/test-data", nil)
	dynMid.ProcessRequest(nil, r, nil)
	if want, got := "x", r.Header.Get("data-foo"); want != got {
		t.Fatalf("wanted header to be %q, got %q", want, got)
	}
	if want, got := "3", r.Header.Get("data-bar-y"); want != got {
		t.Fatalf("wanted header to be %q, got %q", want, got)
	}
}
