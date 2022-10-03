package gateway

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/config"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/user"

	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"

	"github.com/TykTechnologies/tyk/apidef"
	logger "github.com/TykTechnologies/tyk/log"
	"github.com/TykTechnologies/tyk/test"
)

func TestJSVMLogs(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	var buf bytes.Buffer
	log := logrus.New()
	log.Out = &buf
	log.Formatter = new(prefixed.TextFormatter)

	jsvm := JSVM{}
	jsvm.Init(nil, logrus.NewEntry(log), ts.Gw)

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
	ts := StartTest(nil)
	defer ts.Close()

	dynMid := &DynamicMiddleware{
		BaseMiddleware: BaseMiddleware{
			Spec: &APISpec{APIDefinition: &apidef.APIDefinition{}},
			Gw:   ts.Gw,
		},
		MiddlewareClassName: "leakMid",
		Pre:                 true,
	}
	body := "foô \uffff \u0000 \xff bàr"
	req := httptest.NewRequest("GET", "/foo", strings.NewReader(body))
	jsvm := JSVM{}
	jsvm.Init(nil, logrus.NewEntry(log), ts.Gw)

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

	want := body + " appended"

	newBodyInBytes, _ := ioutil.ReadAll(req.Body)
	assert.Equal(t, want, string(newBodyInBytes))

	t.Run("check request body is re-readable", func(t *testing.T) {
		newBodyInBytes, _ = ioutil.ReadAll(req.Body)
		assert.Equal(t, want, string(newBodyInBytes))
	})
}

func TestJSVMSessionMetadataUpdate(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	dynMid := &DynamicMiddleware{
		BaseMiddleware: BaseMiddleware{
			Spec: &APISpec{APIDefinition: &apidef.APIDefinition{}},
			Gw:   ts.Gw,
		},
		MiddlewareClassName: "testJSVMMiddleware",
		Pre:                 false,
		UseSession:          true,
	}
	req := httptest.NewRequest("GET", "/foo", nil)
	jsvm := JSVM{}
	jsvm.Init(nil, logrus.NewEntry(log), ts.Gw)

	s := &user.SessionState{
		MetaData: make(map[string]interface{})}
	s.MetaData["same"] = "same"
	s.MetaData["updated"] = "old"
	s.MetaData["removed"] = "dummy"
	ctxSetSession(req, s, true, ts.Gw.GetConfig().HashKeys)

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
	ts := StartTest(nil)
	defer ts.Close()

	dynMid := &DynamicMiddleware{
		BaseMiddleware: BaseMiddleware{
			Spec: &APISpec{APIDefinition: &apidef.APIDefinition{}},
			Gw:   ts.Gw,
		},
		MiddlewareClassName: "leakMid",
		Pre:                 true,
	}
	req := httptest.NewRequest("GET", "/foo", strings.NewReader("body"))
	jsvm := JSVM{}
	jsvm.Init(nil, logrus.NewEntry(log), ts.Gw)
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
	ts := StartTest(nil)
	defer ts.Close()

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
		BaseMiddleware:      BaseMiddleware{Spec: spec, Proxy: nil, Gw: ts.Gw},
		MiddlewareClassName: "testJSVMData",
		Pre:                 true,
	}
	jsvm := JSVM{}
	jsvm.Init(nil, logrus.NewEntry(log), ts.Gw)
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
func TestJSVM_IgnoreCanonicalHeader(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	const js = `
var testJSVMData = new TykJS.TykMiddleware.NewMiddleware({})

testJSVMData.NewProcessRequest(function(request, session, spec) {
	request.SetHeaders["X-CertificateOuid"] = "X-CertificateOuid"
	return testJSVMData.ReturnData(request, {})
});`
	dynMid := &DynamicMiddleware{
		BaseMiddleware:      BaseMiddleware{Spec: spec, Proxy: nil, Gw: ts.Gw},
		MiddlewareClassName: "testJSVMData",
		Pre:                 true,
	}
	jsvm := JSVM{}
	jsvm.Init(nil, logrus.NewEntry(log), ts.Gw)
	if _, err := jsvm.VM.Run(js); err != nil {
		t.Fatalf("failed to set up js plugin: %v", err)
	}
	dynMid.Spec.JSVM = jsvm

	r := TestReq(t, "GET", "/v1/test-data", nil)
	dynMid.ProcessRequest(nil, r, nil)
	if want, got := NonCanonicalHeaderKey, r.Header.Get(NonCanonicalHeaderKey); want != got {
		t.Fatalf("wanted header to be %q, got %q", want, got)
	}
	r.Header.Del(NonCanonicalHeaderKey)

	c := ts.Gw.GetConfig()
	c.IgnoreCanonicalMIMEHeaderKey = true
	ts.Gw.SetConfig(c)

	dynMid.ProcessRequest(nil, r, nil)
	if want, got := "", r.Header.Get(NonCanonicalHeaderKey); want != got {
		t.Fatalf("wanted header to be %q, got %q", want, got)
	}
	if want, got := NonCanonicalHeaderKey, r.Header[NonCanonicalHeaderKey][0]; want != got {
		t.Fatalf("wanted header to be %q, got %q", want, got)
	}
}

func TestJSVMUserCore(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	const js = `
var testJSVMCore = new TykJS.TykMiddleware.NewMiddleware({})

testJSVMCore.NewProcessRequest(function(request, session, config) {
	request.SetHeaders["global"] = globalVar
	return testJSVMCore.ReturnData(request, {})
});`
	dynMid := &DynamicMiddleware{
		BaseMiddleware:      BaseMiddleware{Spec: spec, Proxy: nil, Gw: ts.Gw},
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
	globalConf := ts.Gw.GetConfig()
	old := globalConf.TykJSPath
	globalConf.TykJSPath = tfile.Name()
	ts.Gw.SetConfig(globalConf)
	defer func() {
		globalConf.TykJSPath = old
		ts.Gw.SetConfig(globalConf)
	}()
	jsvm := JSVM{}
	jsvm.Init(nil, logrus.NewEntry(log), ts.Gw)
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
	ts := StartTest(nil)
	defer ts.Close()

	dynMid := &DynamicMiddleware{
		BaseMiddleware: BaseMiddleware{
			Spec: &APISpec{APIDefinition: &apidef.APIDefinition{}},
			Gw:   ts.Gw,
		},
		MiddlewareClassName: "leakMid",
		Pre:                 true,
	}
	req := httptest.NewRequest("GET", "/foo", nil)
	jsvm := JSVM{}
	jsvm.Init(nil, logrus.NewEntry(log), ts.Gw)

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

	manifest := map[string]string{
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
	`}

	t.Run("Existing endpoint", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()
		bundle := ts.RegisterBundle("jsvm_make_http_request", manifest)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
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
		ts := StartTest(nil)
		defer ts.Close()
		bundle := ts.RegisterBundle("jsvm_make_http_request", manifest)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/sample"
			spec.ConfigData = map[string]interface{}{
				"base_url": ts.URL,
			}
			spec.CustomMiddlewareBundle = bundle
		})

		ts.Run(t, test.TestCase{Path: "/sample", Code: 404})
	})

	t.Run("Endpoint with query", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()
		bundle := ts.RegisterBundle("jsvm_make_http_request", manifest)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/sample"
			spec.ConfigData = map[string]interface{}{
				"base_url": ts.URL,
			}
			spec.CustomMiddlewareBundle = bundle
		}, func(spec *APISpec) {
			spec.Proxy.ListenPath = "/api"
		})

		ts.Run(t, test.TestCase{Path: "/sample", BodyMatch: `/api/get\?param1=dummy`, Code: 200})
	})

	t.Run("Endpoint with skip cleaning", func(t *testing.T) {
		conf := func(conf *config.Config) {
			conf.HttpServerOptions.SkipURLCleaning = true
			conf.HttpServerOptions.OverrideDefaults = true
		}

		ts := StartTest(conf)
		defer ts.Close()
		bundle := ts.RegisterBundle("jsvm_make_http_request", manifest)
		ts.TestServerRouter.SkipClean(true)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/sample"
			spec.ConfigData = map[string]interface{}{
				"base_url": ts.URL,
			}
			spec.CustomMiddlewareBundle = bundle
		}, func(spec *APISpec) {
			spec.Proxy.ListenPath = "/api"
		})

		ts.Run(t, test.TestCase{Path: "/sample/99999-XXXX+%2F%2F+dog+9+fff%C3%A9o+party", BodyMatch: `URI":"/sample/99999-XXXX\+%2F%2F\+dog\+9\+fff%C3%A9o\+party"`, Code: 200})
	})
}

func TestJSVMBase64(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	jsvm := JSVM{}
	jsvm.Init(nil, logrus.NewEntry(log), ts.Gw)

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

func TestJSVMStagesRequest(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	pre := `var pre = new TykJS.TykMiddleware.NewMiddleware({});

pre.NewProcessRequest(function(request, session) {
    // You can log to Tyk console output by calloing the built-in log() function:
    log("Running sample  PRE PROCESSOR JSVM middleware")
    
    // Set headers in an outbound request
    request.SetHeaders["Pre"] = "foobar";
    // Add or delete request parmeters, these are encoded for the request as needed.
    request.AddParams["pre"] = "foobar";
    
    // You MUST return both the request and session metadata    
    return pre.ReturnData(request, {"pre": "foobar"});
});`

	post := `var post = new TykJS.TykMiddleware.NewMiddleware({});

post.NewProcessRequest(function(request, session) {
    // You can log to Tyk console output by calloing the built-in log() function:
    log("Running sample  POST PROCESSOR JSVM middleware")
    
    // Set headers in an outbound request
    request.SetHeaders["Post"] = "foobar";
    // Add or delete request parmeters, these are encoded for the request as needed.
    request.AddParams["post"] = "foobar";
    
    // You MUST return both the request and session metadata    
    return post.ReturnData(request, {"post": "foobar"});
});`

	t.Run("Bundles", func(t *testing.T) {
		bundle := ts.RegisterBundle("jsvm_stages", map[string]string{
			"manifest.json": `
		{
		    "file_list": [],
		    "custom_middleware": {
		        "driver": "otto",
		        "pre": [{
		            "name": "pre",
		            "path": "pre.js"
		        }],
				"post": [{
		            "name": "post",
		            "path": "post.js"
		        }]
		    }
		}
	`,
			"pre.js":  pre,
			"post.js": post,
		})

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test"
			spec.CustomMiddlewareBundle = bundle
			spec.CustomMiddleware.Driver = apidef.OttoDriver
		})

		ts.Run(t, []test.TestCase{
			{Path: "/test", Code: 200, BodyMatch: `"Pre":"foobar"`},
			{Path: "/test", Code: 200, BodyMatch: `"Post":"foobar"`},
		}...)
	})

	t.Run("Files", func(t *testing.T) {
		// Object names are forced to be "pre" and "post"
		ts.RegisterJSFileMiddleware("jsvm_file_test", map[string]string{
			"pre/pre.js":   pre,
			"post/post.js": post,
		})

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = "jsvm_file_test"
			spec.Proxy.ListenPath = "/test"
			spec.CustomMiddleware.Driver = apidef.OttoDriver
		})

		ts.Run(t, []test.TestCase{
			{Path: "/test", Code: 200, BodyMatch: `"Pre":"foobar"`},
			{Path: "/test", Code: 200, BodyMatch: `"Post":"foobar"`},
		}...)
	})

	t.Run("API definition", func(t *testing.T) {
		// Write to non APIID folder
		ts.RegisterJSFileMiddleware("jsvm_api", map[string]string{
			"pre.js":  pre,
			"post.js": post,
		})

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test"
			spec.CustomMiddleware = apidef.MiddlewareSection{
				Driver: apidef.OttoDriver,
				Pre: []apidef.MiddlewareDefinition{{
					Name: "pre",
					Path: ts.Gw.GetConfig().MiddlewarePath + "/jsvm_api/pre.js",
				}},
				Post: []apidef.MiddlewareDefinition{{
					Name: "post",
					Path: ts.Gw.GetConfig().MiddlewarePath + "/jsvm_api/post.js",
				}},
			}
		})

		ts.Run(t, []test.TestCase{
			{Path: "/test", Code: 200, BodyMatch: `"Pre":"foobar"`},
			{Path: "/test", Code: 200, BodyMatch: `"Post":"foobar"`},
		}...)
	})
}

func TestMiniRequestObject_ReconstructParams(t *testing.T) {
	const exampleURL = "http://example.com/get?b=1&c=2&a=3"
	r, _ := http.NewRequest(http.MethodGet, exampleURL, nil)
	mr := MiniRequestObject{}

	t.Run("Don't touch queries if no change on params", func(t *testing.T) {
		mr.ReconstructParams(r)
		assert.Equal(t, exampleURL, r.URL.String())
	})

	t.Run("Update params", func(t *testing.T) {
		mr.AddParams = map[string]string{
			"d": "4",
		}
		mr.DeleteParams = append(mr.DeleteHeaders, "b")
		mr.ReconstructParams(r)

		assert.Equal(t, url.Values{
			"a": []string{"3"},
			"c": []string{"2"},
			"d": []string{"4"},
		}, r.URL.Query())
	})
}

func TestJSVM_Auth(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	bundle := ts.RegisterBundle("custom_auth", map[string]string{
		"manifest.json": `{
			"file_list": [
				"testmw.js"
			],
			"custom_middleware": {
				"pre": null,
				"post": null,
				"post_key_auth": null,
				"auth_check": {
					"name": "ottoAuthExample",
					"path": "testmw.js",
					"require_session": false
				},
				"response": null,
				"driver": "otto",
				"id_extractor": {
					"extract_from": "",
					"extract_with": "",
					"extractor_config": null
				}
			},
			"checksum": "65694908d609b14df0e280c1a95a8ca4",
			"signature": ""
		}`,
		"testmw.js": `log("====> JS Auth initialising");

		var ottoAuthExample = new TykJS.TykMiddleware.NewMiddleware({});
		
		ottoAuthExample.NewProcessRequest(function(request, session) {
			log("----> Running ottoAuthExample JSVM Auth Middleware")
		
			var thisToken = request.Headers["Authorization"];
		
			if (thisToken == undefined) {
				// no token at all?
				request.ReturnOverrides.ResponseCode = 401
				request.ReturnOverrides.ResponseError = 'Header missing (JS middleware)'
				return ottoAuthExample.ReturnData(request, {});
			}
		
			if (thisToken != "foobar") {
				request.ReturnOverrides.ResponseCode = 401
				request.ReturnOverrides.ResponseError = 'Not authorized (JS middleware)'
				return ottoAuthExample.ReturnData(request, {});
			}
		
			log("auth is ok")
		
			var thisSession = {
				"allowance": 100,
				"rate": 100,
				"per": 1,
				"quota_max": -1,
				"quota_renews": 1906121006,
				"expires": 1906121006,
				"access_rights": {}
			};
		
			return ottoAuthExample.ReturnAuthData(request, thisSession);
		});
		
		// Ensure init with a post-declaration log message
		log("====> JS Auth initialised");
		`,
	})
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/sample"
		spec.ConfigData = map[string]interface{}{
			"base_url": ts.URL,
		}
		spec.CustomMiddlewareBundle = bundle
		spec.EnableCoProcessAuth = true
		spec.UseKeylessAccess = false
	})
	ts.Run(t,
		test.TestCase{Path: "/sample", Code: http.StatusUnauthorized, BodyMatchFunc: func(b []byte) bool {
			return strings.Contains(string(b), "Header missing (JS middleware)")
		}},
		test.TestCase{Path: "/sample", Code: http.StatusUnauthorized, BodyMatchFunc: func(b []byte) bool {
			return strings.Contains(string(b), "Not authorized (JS middleware)")
		},
			Headers: map[string]string{"Authorization": "foo"},
		},
		test.TestCase{Path: "/sample", Code: http.StatusOK, Headers: map[string]string{
			"Authorization": "foobar",
		}},
	)
}
