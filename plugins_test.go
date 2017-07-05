package main

import (
	"bytes"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestJSVMLogs(t *testing.T) {
	var buf bytes.Buffer
	jsvm := &JSVM{}
	jsvm.Init()
	jsvm.Log = logrus.New()
	jsvm.Log.Out = &buf
	jsvm.Log.Formatter = new(prefixed.TextFormatter)

	const in = `
log("foo")
log('{"x": "y"}')
rawlog("foo")
rawlog('{"x": "y"}')
`
	// note how the logger leaves spaces at the end
	want := []string{
		`time=TIME level=info msg=foo type=log-msg `,
		`time=TIME level=info msg="{\"x\": \"y\"}" type=log-msg `,
		`foo`,
		`{"x": "y"}`,
	}
	if _, err := jsvm.VM.Run(in); err != nil {
		t.Fatalf("failed to run js: %v", err)
	}
	got := strings.Split(strings.Trim(buf.String(), "\n"), "\n")
	i := 0
	timeRe := regexp.MustCompile(`time="[^"]*"`)
	for _, line := range got {
		if i >= len(want) {
			t.Logf("too many lines")
			t.Fail()
			break
		}
		s := timeRe.ReplaceAllString(line, "time=TIME")
		if s != line && !strings.Contains(s, "type=log-msg") {
			continue // log line from elsewhere (async)
		}
		if s != want[i] {
			t.Logf("%s != %s", s, want[i])
			t.Fail()
		}
		i++
	}
}

func TestJSVMProcessTimeout(t *testing.T) {
	dynMid := &DynamicMiddleware{
		TykMiddleware: &TykMiddleware{
			Spec: &APISpec{APIDefinition: &apidef.APIDefinition{}},
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
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.RawData = map[string]interface{}{
		"config_data": map[string]interface{}{
			"foo": "bar",
		},
	}
	const js = `
var testJSVMData = new TykJS.TykMiddleware.NewMiddleware({});

testJSVMData.NewProcessRequest(function(request, session, config) {
	request.SetHeaders["data-foo"] = config.config_data.foo;
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

	r := testReq(t, "GET", "/v1/test-data", nil)
	dynMid.ProcessRequest(nil, r, nil)
	if want, got := "bar", r.Header.Get("data-foo"); want != got {
		t.Fatalf("wanted header to be %q, got %q", want, got)
	}
}
