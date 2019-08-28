package gateway

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/user"

	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	logger "github.com/TykTechnologies/tyk/log"
	"github.com/TykTechnologies/tyk/test"
)

func TestJSVMLogs(t *testing.T) {
	var buf bytes.Buffer
	log := logrus.New()
	log.Out = &buf
	log.Formatter = new(prefixed.TextFormatter)

	jsvm := JSVM{}
	jsvm.Init(nil, logrus.NewEntry(log))

	jsvm.RawLog = logrus.New()
	jsvm.RawLog.Out = &buf
	jsvm.RawLog.Formatter = new(logger.RawFormatter)

	const in = `
log("foo")
log('{"x": "y"}')
rawlog("foo")
rawlog('{"x": "y"}')
`

	want := []string{
		`time=TIME level=info msg=foo prefix=jsvm type=log-msg`,
		`time=TIME level=info msg="{"x": "y"}" prefix=jsvm type=log-msg`,
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

func TestJSVMBody(t *testing.T) {
	dynMid := &DynamicMiddleware{
		BaseMiddleware: BaseMiddleware{
			Spec: &APISpec{APIDefinition: &apidef.APIDefinition{}},
		},
		MiddlewareClassName: "leakMid",
		Pre:                 true,
	}
	body := "foô \uffff \u0000 \xff bàr"
	req := httptest.NewRequest("GET", "/foo", strings.NewReader(body))
	jsvm := JSVM{}
	jsvm.Init(nil, logrus.NewEntry(log))

	const js = `
var leakMid = new TykJS.TykMiddleware.NewMiddleware({})

leakMid.NewProcessRequest(function(request, session) {
	request.Body += " appended"
	return leakMid.ReturnData(request, session.meta_data)
});`
	if _, err := jsvm.VM.Run(js); err != nil {
		t.Fatalf("failed to set up js plugin: %v", err)
	}
	dynMid.Spec.JSVM = jsvm
	dynMid.ProcessRequest(nil, req, nil)

	bs, err := ioutil.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("failed to read final body: %v", err)
	}
	want := body + " appended"
	if got := string(bs); want != got {
		t.Fatalf("JS plugin broke non-UTF8 body %q into %q",
			want, got)
	}
}

func TestJSVMSessionMetadataUpdate(t *testing.T) {
	dynMid := &DynamicMiddleware{
		BaseMiddleware: BaseMiddleware{
			Spec: &APISpec{APIDefinition: &apidef.APIDefinition{}},
		},
		MiddlewareClassName: "testJSVMMiddleware",
		Pre:                 false,
		UseSession:          true,
	}
	req := httptest.NewRequest("GET", "/foo", nil)
	jsvm := JSVM{}
	jsvm.Init(nil, logrus.NewEntry(log))

	s := &user.SessionState{MetaData: make(map[string]interface{})}
	s.MetaData["same"] = "same"
	s.MetaData["updated"] = "old"
	s.MetaData["removed"] = "dummy"
	ctxSetSession(req, s, "", true)

	const js = `
var testJSVMMiddleware = new TykJS.TykMiddleware.NewMiddleware({});

testJSVMMiddleware.NewProcessRequest(function(request, session) {
	return testJSVMMiddleware.ReturnData(request, {same: "same", updated: "new"})
});`
	if _, err := jsvm.VM.Run(js); err != nil {
		t.Fatalf("failed to set up js plugin: %v", err)
	}
	dynMid.Spec.JSVM = jsvm
	_, _ = dynMid.ProcessRequest(nil, req, nil)

	updatedSession := ctx.GetSession(req)

	if updatedSession.MetaData["same"] != "same" {
		t.Fatal("Failed to update session metadata for same")
	}

	if updatedSession.MetaData["updated"] != "new" {
		t.Fatal("Failed to update session metadata for updated")
	}

	if updatedSession.MetaData["removed"] != nil {
		t.Fatal("Failed to update session metadata for removed")
	}
}

func TestJSVMProcessTimeout(t *testing.T) {
	dynMid := &DynamicMiddleware{
		BaseMiddleware: BaseMiddleware{
			Spec: &APISpec{APIDefinition: &apidef.APIDefinition{}},
		},
		MiddlewareClassName: "leakMid",
		Pre:                 true,
	}
	req := httptest.NewRequest("GET", "/foo", strings.NewReader("body"))
	jsvm := JSVM{}
	jsvm.Init(nil, logrus.NewEntry(log))
	jsvm.Timeout = time.Millisecond

	// this js plugin just loops forever, keeping Otto at 100% CPU
	// usage and running forever.
	const js = `
var leakMid = new TykJS.TykMiddleware.NewMiddleware({})

leakMid.NewProcessRequest(function(request, session) {
	while (true) {
	}
	return leakMid.ReturnData(request, session.meta_data)
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
	spec.ConfigData = map[string]interface{}{
		"foo": "bar",
	}
	const js = `
var testJSVMData = new TykJS.TykMiddleware.NewMiddleware({})

testJSVMData.NewProcessRequest(function(request, session, spec) {
	request.SetHeaders["data-foo"] = spec.config_data.foo
	return testJSVMData.ReturnData(request, {})
});`
	dynMid := &DynamicMiddleware{
		BaseMiddleware:      BaseMiddleware{Spec: spec, Proxy: nil},
		MiddlewareClassName: "testJSVMData",
		Pre:                 true,
	}
	jsvm := JSVM{}
	jsvm.Init(nil, logrus.NewEntry(log))
	if _, err := jsvm.VM.Run(js); err != nil {
		t.Fatalf("failed to set up js plugin: %v", err)
	}
	dynMid.Spec.JSVM = jsvm

	r := TestReq(t, "GET", "/v1/test-data", nil)
	dynMid.ProcessRequest(nil, r, nil)
	if want, got := "bar", r.Header.Get("data-foo"); want != got {
		t.Fatalf("wanted header to be %q, got %q", want, got)
	}
}

func TestJSVMReturnOverridesFullResponse(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.ConfigData = map[string]interface{}{
		"foo": "bar",
	}
	const js = `
var testJSVMData = new TykJS.TykMiddleware.NewMiddleware({})

testJSVMData.NewProcessRequest(function(request, session, config) {
	request.ReturnOverrides.ResponseError = "Foobarbaz"
	request.ReturnOverrides.ResponseCode = 200
	request.ReturnOverrides.ResponseHeaders = {
		"X-Foo": "Bar",
		"X-Baz": "Qux"
	}
	return testJSVMData.ReturnData(request, {})
});`
	dynMid := &DynamicMiddleware{
		BaseMiddleware:      BaseMiddleware{Spec: spec, Proxy: nil},
		MiddlewareClassName: "testJSVMData",
		Pre:                 true,
	}
	jsvm := JSVM{}
	jsvm.Init(nil, logrus.NewEntry(log))
	if _, err := jsvm.VM.Run(js); err != nil {
		t.Fatalf("failed to set up js plugin: %v", err)
	}
	dynMid.Spec.JSVM = jsvm

	rec := httptest.NewRecorder()
	r := TestReq(t, "GET", "/v1/test-data", nil)
	dynMid.ProcessRequest(rec, r, nil)

	wantBody := "Foobarbaz"
	gotBody := rec.Body.String()
	if wantBody != gotBody {
		t.Fatalf("wanted body to be %q, got %q", wantBody, gotBody)
	}
	if want, got := "Bar", rec.HeaderMap.Get("x-foo"); got != want {
		t.Fatalf("wanted header to be %q, got %q", want, got)
	}
	if want, got := "Qux", rec.HeaderMap.Get("x-baz"); got != want {
		t.Fatalf("wanted header to be %q, got %q", want, got)
	}

	if want := 200; rec.Code != 200 {
		t.Fatalf("wanted code to be %d, got %d", want, rec.Code)
	}
}

func TestJSVMReturnOverridesError(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.ConfigData = map[string]interface{}{
		"foo": "bar",
	}
	const js = `
var testJSVMData = new TykJS.TykMiddleware.NewMiddleware({})

testJSVMData.NewProcessRequest(function(request, session, config) {
	request.ReturnOverrides.ResponseError = "Foobarbaz"
	request.ReturnOverrides.ResponseCode = 401
	return testJSVMData.ReturnData(request, {})
});`
	dynMid := &DynamicMiddleware{
		BaseMiddleware:      BaseMiddleware{Spec: spec, Proxy: nil},
		MiddlewareClassName: "testJSVMData",
		Pre:                 true,
	}
	jsvm := JSVM{}
	jsvm.Init(nil, logrus.NewEntry(log))
	if _, err := jsvm.VM.Run(js); err != nil {
		t.Fatalf("failed to set up js plugin: %v", err)
	}
	dynMid.Spec.JSVM = jsvm

	r := TestReq(t, "GET", "/v1/test-data", nil)
	err, code := dynMid.ProcessRequest(nil, r, nil)

	if want := 401; code != 401 {
		t.Fatalf("wanted code to be %d, got %d", want, code)
	}

	wantBody := "Foobarbaz"
	if !strings.Contains(err.Error(), wantBody) {
		t.Fatalf("wanted body to contain to be %v, got %v", wantBody, err.Error())
	}
}

func TestJSVMUserCore(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	const js = `
var testJSVMCore = new TykJS.TykMiddleware.NewMiddleware({})

testJSVMCore.NewProcessRequest(function(request, session, config) {
	request.SetHeaders["global"] = globalVar
	return testJSVMCore.ReturnData(request, {})
});`
	dynMid := &DynamicMiddleware{
		BaseMiddleware:      BaseMiddleware{Spec: spec, Proxy: nil},
		MiddlewareClassName: "testJSVMCore",
		Pre:                 true,
	}
	tfile, err := ioutil.TempFile("", "tykjs")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tfile, `var globalVar = "globalValue"`); err != nil {
		t.Fatal(err)
	}
	globalConf := config.Global()
	old := globalConf.TykJSPath
	globalConf.TykJSPath = tfile.Name()
	config.SetGlobal(globalConf)
	defer func() {
		globalConf.TykJSPath = old
		config.SetGlobal(globalConf)
	}()
	jsvm := JSVM{}
	jsvm.Init(nil, logrus.NewEntry(log))
	if _, err := jsvm.VM.Run(js); err != nil {
		t.Fatalf("failed to set up js plugin: %v", err)
	}
	dynMid.Spec.JSVM = jsvm

	r := TestReq(t, "GET", "/foo", nil)
	dynMid.ProcessRequest(nil, r, nil)

	if want, got := "globalValue", r.Header.Get("global"); want != got {
		t.Fatalf("wanted header to be %q, got %q", want, got)
	}
}

func TestJSVMRequestScheme(t *testing.T) {
	dynMid := &DynamicMiddleware{
		BaseMiddleware: BaseMiddleware{
			Spec: &APISpec{APIDefinition: &apidef.APIDefinition{}},
		},
		MiddlewareClassName: "leakMid",
		Pre:                 true,
	}
	req := httptest.NewRequest("GET", "/foo", nil)
	jsvm := JSVM{}
	jsvm.Init(nil, logrus.NewEntry(log))

	const js = `
var leakMid = new TykJS.TykMiddleware.NewMiddleware({})
leakMid.NewProcessRequest(function(request, session) {
	var test = request.Scheme += " appended"
	var responseObject = {
        Body: test,
        Code: 200
    }
	return leakMid.ReturnData(responseObject, session.meta_data)
});`
	if _, err := jsvm.VM.Run(js); err != nil {
		t.Fatalf("failed to set up js plugin: %v", err)
	}
	dynMid.Spec.JSVM = jsvm
	dynMid.ProcessRequest(nil, req, nil)

	bs, err := ioutil.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("failed to read final body: %v", err)
	}
	want := "http" + " appended"
	if got := string(bs); want != got {
		t.Fatalf("JS plugin broke non-UTF8 body %q into %q",
			want, got)
	}
}

func TestTykMakeHTTPRequest(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	bundle := RegisterBundle("jsvm_make_http_request", map[string]string{
		"manifest.json": `
		{
		    "file_list": [],
		    "custom_middleware": {
		        "driver": "otto",
		        "pre": [{
		            "name": "testTykMakeHTTPRequest",
		            "path": "middleware.js"
		        }]
		    }
		}
	`,
		"middleware.js": `
	var testTykMakeHTTPRequest = new TykJS.TykMiddleware.NewMiddleware({})

	testTykMakeHTTPRequest.NewProcessRequest(function(request, session, spec) {
		var newRequest = {
			"Method": "GET",
			"Headers": {"Accept": "application/json"},
			"Domain": spec.config_data.base_url,
			"Resource": "/api/get?param1=dummy"
		}

		var resp = TykMakeHttpRequest(JSON.stringify(newRequest));
		var usableResponse = JSON.parse(resp);

		if(usableResponse.Code > 400) {
			request.ReturnOverrides.ResponseCode = usableResponse.code
			request.ReturnOverrides.ResponseError = "error"
		}

		request.Body = usableResponse.Body

		return testTykMakeHTTPRequest.ReturnData(request, {})
	});
	`})

	t.Run("Existing endpoint", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/sample"
			spec.ConfigData = map[string]interface{}{
				"base_url": ts.URL,
			}
			spec.CustomMiddlewareBundle = bundle
		}, func(spec *APISpec) {
			spec.Proxy.ListenPath = "/api"
		})

		ts.Run(t, test.TestCase{Path: "/sample", Code: 200})
	})

	t.Run("Nonexistent endpoint", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/sample"
			spec.ConfigData = map[string]interface{}{
				"base_url": ts.URL,
			}
			spec.CustomMiddlewareBundle = bundle
		})

		ts.Run(t, test.TestCase{Path: "/sample", Code: 404})
	})

	t.Run("Endpoint with query", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/sample"
			spec.ConfigData = map[string]interface{}{
				"base_url": ts.URL,
			}
			spec.CustomMiddlewareBundle = bundle
		}, func(spec *APISpec) {
			spec.Proxy.ListenPath = "/api"
		})

		ts.Run(t, test.TestCase{Path: "/sample", BodyMatch: "/api/get?param1=dummy", Code: 200})
	})

	t.Run("Endpoint with skip cleaning", func(t *testing.T) {
		ts.Close()
		globalConf := config.Global()
		globalConf.HttpServerOptions.SkipURLCleaning = true
		globalConf.HttpServerOptions.OverrideDefaults = true
		config.SetGlobal(globalConf)

		prevSkipClean := defaultTestConfig.HttpServerOptions.OverrideDefaults &&
			defaultTestConfig.HttpServerOptions.SkipURLCleaning
		testServerRouter.SkipClean(true)
		defer testServerRouter.SkipClean(prevSkipClean)

		ts := StartTest()
		defer ts.Close()
		defer ResetTestConfig()

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/sample"
			spec.ConfigData = map[string]interface{}{
				"base_url": ts.URL,
			}
			spec.CustomMiddlewareBundle = bundle
		}, func(spec *APISpec) {
			spec.Proxy.ListenPath = "/api"
		})

		ts.Run(t, test.TestCase{Path: "/sample/99999-XXXX+%2F%2F+dog+9+fff%C3%A9o+party", BodyMatch: "URI\":\"/sample/99999-XXXX+%2F%2F+dog+9+fff%C3%A9o+party", Code: 200})
	})
}

func TestJSVMBase64(t *testing.T) {
	jsvm := JSVM{}
	jsvm.Init(nil, logrus.NewEntry(log))

	inputString := "teststring"
	inputB64 := "dGVzdHN0cmluZw=="
	jwtPayload := "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
	decodedJwtPayload := `{"sub":"1234567890","name":"John Doe","iat":1516239022}`

	t.Run("b64dec with simple string input", func(t *testing.T) {
		v, err := jsvm.VM.Run(`b64dec("` + inputB64 + `")`)
		if err != nil {
			t.Fatalf("b64dec call failed: %s", err.Error())
		}
		if s := v.String(); s != inputString {
			t.Fatalf("wanted '%s', got '%s'", inputString, s)
		}
	})

	t.Run("b64dec with a JWT payload", func(t *testing.T) {
		v, err := jsvm.VM.Run(`b64dec("` + jwtPayload + `")`)
		if err != nil {
			t.Fatalf("b64dec call failed: %s", err.Error())
		}
		if s := v.String(); s != decodedJwtPayload {
			t.Fatalf("wanted '%s', got '%s'", decodedJwtPayload, s)
		}
	})

	t.Run("b64enc with simple string input", func(t *testing.T) {
		v, err := jsvm.VM.Run(`b64enc("` + inputString + `")`)
		if err != nil {
			t.Fatalf("b64enc call failed: %s", err.Error())
		}
		if s := v.String(); s != inputB64 {
			t.Fatalf("wanted '%s', got '%s'", inputB64, s)
		}
	})

	t.Run("rawb64dec with simple string input", func(t *testing.T) {
		v, err := jsvm.VM.Run(`rawb64dec("` + jwtPayload + `")`)
		if err != nil {
			t.Fatalf("rawb64dec call failed: %s", err.Error())
		}
		if s := v.String(); s != decodedJwtPayload {
			t.Fatalf("wanted '%s', got '%s'", decodedJwtPayload, s)
		}
	})

	t.Run("rawb64enc with simple string input", func(t *testing.T) {
		jsvm.VM.Set("input", decodedJwtPayload)
		v, err := jsvm.VM.Run(`rawb64enc(input)`)
		if err != nil {
			t.Fatalf("rawb64enc call failed: %s", err.Error())
		}
		if s := v.String(); s != jwtPayload {
			t.Fatalf("wanted '%s', got '%s'", jwtPayload, s)
		}
	})
}
