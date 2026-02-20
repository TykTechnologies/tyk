Table of Contents
=================

* [Tyk testing guide](#tyk-testing-guide)
    * [Initializing test server](#initializing-test-server)
    * [Loading and configuring APIs](#loading-and-configuring-apis)
    * [Running the tests](#running-the-tests)
    * [Changing config variables](#changing-config-variables)
    * [Upstream test server](#upstream-test-server)
    * [Coprocess plugin testing](#coprocess-plugin-testing)
    * [Creating user sessions](#creating-user-sessions)
    * [Mocking dashboard](#mocking-dashboard)
    * [Mocking RPC (Hybrid)](#mocking-rpc-hybrid)
    * [Mocking DNS](#mocking-dns)
* [Test Framework](#test-framework)
    

## Tyk testing guide
 
When it comes to the tests, one of the main questions is how to keep balance between expressivity, extendability, repeatability and performance. There are countless discussions if you should write integration or unit tests, should your mock or not, should you write tests first or after and etc. Since you will never find the right answer, on a growing code base, multiple people start introducing own methodology and distinct test helpers. Even looking at our quite small code base, you can find like 3-4 ways to write the same test.

This document describes Tyk test framework and unified guidelines on writing tests.

Main points of the test framework are:
- All tests run HTTP requests though the full HTTP stack, same as user will do
- Test definition logic separated from test runner.
- Official mocks for the Dashboard, RPC, and Bundler
- Most of the time, you will need a gateway instance to use the gateway functions and properties

Framework located inside "github.com/TykTechnologies/tyk/test" package.
See its API docs https://godoc.org/github.com/TykTechnologies/tyk/test

Let’s learn by example:

```go
func genAuthHeader(username, password string) string {
	toEncode := strings.Join([]string{username, password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(toEncode))
	return fmt.Sprintf("Basic %s", encodedPass)
}

func TestBasicAuth(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	session := ts.testPrepareBasicAuth(false)

	validPassword := map[string]string{"Authorization": genAuthHeader("user", "password")}
	wrongPassword := map[string]string{"Authorization": genAuthHeader("user", "wrong")}
	wrongFormat := map[string]string{"Authorization": genAuthHeader("user", "password:more")}
	malformed := map[string]string{"Authorization": "not base64"}

	ts.Run(t, []test.TestCase{
		// Create base auth based key
		{Method: "POST", Path: "/tyk/keys/defaultuser", Data: session, AdminAuth: true, Code: 200},
		{Method: "GET", Path: "/", Code: 401, BodyMatch: `Authorization field missing`},
		{Method: "GET", Path: "/", Headers: validPassword, Code: 200},
		{Method: "GET", Path: "/", Headers: wrongPassword, Code: 401},
		{Method: "GET", Path: "/", Headers: wrongFormat, Code: 400, BodyMatch: `Attempted access with malformed header, values not in basic auth format`},
		{Method: "GET", Path: "/", Headers: malformed, Code: 400, BodyMatch: `Attempted access with malformed header, auth data not encoded correctly`},
	}...)
}
```

[Direct Github link](https://github.com/matiasinsaurralde/tyk/blob/4b6e0290ee36f6721b8d5343051bf343900b5943/mw_basic_auth_test.go)

And now compare it with previous Go style approach:

```go
func TestBasicAuthWrongPassword(t *testing.T) {
    spec := createSpecTest(t, basicAuthDef)
    session := createBasicAuthSession()
    username := "4321"

    // Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
    spec.SessionManager.UpdateSession("default4321", session, 60)

    to_encode := strings.Join([]string{username, "WRONGPASSTEST"}, ":")
    encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))

    recorder := httptest.NewRecorder()
    req := testReq(t, "GET", "/", nil)
    req.Header.Set("Authorization", fmt.Sprintf("Basic %s", encodedPass))

    chain := getBasicAuthChain(spec)
    chain.ServeHTTP(recorder, req)

    if recorder.Code == 200 {
        t.Error("Request should have failed and returned non-200 code!: \n", recorder.Code)
    }

    if recorder.Code != 401 {
        t.Error("Request should have returned 401 code!: \n", recorder.Code)
    }

    if recorder.Header().Get("WWW-Authenticate") == "" {
        t.Error("Request should have returned WWW-Authenticate header!: \n")
    }
}
```

[Direct Github link](https://github.com/matiasinsaurralde/tyk/blob/2a9d7d5b6c289ac75dfa9b4e9c4527f1041d7daf/mw_basic_auth_test.go#L246:1)

Note that in the last “classic” way we defined only 1 test case, while in with our new framework we defined 6, all of them repeatable, and share the same assertion and test runner logic provided by framework. 

Now lets review tests written with a new framework piece by piece.
### Initializing test server
One of the core ideas, is that tests should be as close as possible to real users. In order to implement it, framework provides you a way to programmatically start and stop full Gateway HTTP stack using `tykTestServer` object, like this:

```go
ts := StartTest(nil)
defer ts.Close()
```

## About StartTest
StarTest() is a function that will and setup a gateway instance, it receive as parameters:

- genConf(*config.Config): is a function to override the gateway config set by default, if you don't want to override any config then you must sent a nil value. Example:
```
conf := func(confi *config.Config) {
		confi.EventHandlers = eventsConf.EventHandlers
	}
ts := StartTest(conf)
defer ts.Close()
```
- testConfig: you can configure server behavior using few variable, like setting control API on a separate port, by providing `TestConfig` object. Here is the list of all possible arguments:

```go
	ts := gateway.StartTest(nil, gateway.TestConfig{
           // Run control API on a separate port
           sepatateControlAPI: true,
           // Add delay after each test case, if you code depend on timing
           // Bad practice, but sometimes needed
           delay: 10 * time.Millisecond,
           // Emulate that Gateway restarted using SIGUSR2
           hotReload: true,
           // Emulate that listener will 
           overrideDefaults, true,
           // if you want to skip the redis cleaning process
           SkipEmptyRedis: false
    })
    defer ts.Close()
```

StartTest() returns a Test object that contains:

- URL: where the gateway is reachable
- testRunner: the HttpTestRunner to use to consume and test endpoints
- config: a TestConfig object on how to run the test, we pass this as param to `StartTest()` when starting the test
- Gw: a full gateway instance, from which we can call any gateway function, get the current gateway config or even modify it
- HttpHandler: the HTTP server

When you create a new server, it initialize gateway itself, starts listener on random port, setup required global variables and etc. It is very similar to what happens when you start gateway process, but in this case you can start, stop and reload it on demand.

To close the server simply call `Test#Close` method, which will ensure that all the listeners will be properly closed. 

### Loading and configuring APIs

```go
ts := gateway.StartTest(nil)
defer ts.Close()

ts.Gw.buildAndLoadAPI(func(spec *APISpec) {
    spec.UseBasicAuth = true
    spec.UseKeylessAccess = false
    spec.Proxy.ListenPath = "/"
    spec.OrgID = "default"
})
```

Basic idea that you have default bare minimum API definition, which you can configure using generator function, to set state required for the test. API then will be loaded into the Gateway, and will be ready to be used inside tests.

If you need to load multiple APIs at the same time, `buildAndLoadAPI` support variadic number of arguments: `buildAndLoadAPI(<fn1>, <fn2>, ...)`

You can also call it without arguments at all, in this case it will load default API definition: `buildAndLoadAPI()`

In fact, this function is mashup of 2 lower level functions: `buildAPI` and `loadAPI`, both returning `[]*APISpec` array. In some cases you may need to build API template, and with some smaller modifications load it on demand in different tests. So it can look like:

```go
ts := gateway.StartTest(nil)
defer ts.Close()

spec := buildAPI(<fn>)
...
spec.SomeField = "Case1"
ts.Gw.loadAPI(spec)
...
spec.SomeField = "Case2"
ts.Gw.loadAPI(spec)
```

Updating variables inside API version can be tricky, because API version object is inside `Versions` map, and direct manipulations with map value is prohibited. To simplify this process, there is special helper `updateAPIVersion`, which can be used like this:

```go
ts := gateway.StartTest(nil)
defer ts.Close()

ts.Gw.updateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
    v.Paths.BlackList = []string{"/blacklist/literal", "/blacklist/{id}/test"}
    v.UseExtendedPaths = false
})
```

In some cases updating API definition via Go structures can be a bit complex, and you may want to update API definition directly via JSON unmarshaling:

```go
 ts := gateway.StartTest(nil)
 defer ts.Close()

 ts.Gw.updateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
     json.Unmarshal([]byte(`[
         {
            "path": "/ignored/literal",
            "method_actions": {"GET": {"action": "no_action"}}
        },
        {
            "path": "/ignored/{id}/test",
            "method_actions": {"GET": {"action": "no_action"}}
        }
    ]`), &v.ExtendedPaths.Ignored)
 })
 ```

### Running the tests

```go
ts.Run(t, []test.TestCase{
        // Create base auth based key
        {Method: "POST", Path: "/tyk/keys/defaultuser", Data: session, AdminAuth: true, Code: 200},
        {Method: "GET", Path: "/", Code: 401, BodyMatch: `Authorization field missing`},
        {Method: "GET", Path: "/", Headers: validPassword, Code: 200},
        {Method: "GET", Path: "/", Headers: wrongPassword, Code: 401},
        {Method: "GET", Path: "/", Headers: wrongFormat, Code: 400, BodyMatch: `Attempted access with malformed header, values not in basic auth format`},
        {Method: "GET", Path: "/", Headers: malformed, Code: 400, BodyMatch: `Attempted access with malformed header, auth data not encoded correctly`},
    }...)
}
```

Tests are defined using new `test` package `TestCase` structure, which allows you to define both http request details and response assertions. For example `{Method: "GET", Path: "/", Headers: validPassword, Code: 200}` tells to make a `GET` request to `/` path, with specified headers. After request is made, it will assert response status code with given value.

```go
type TestCase struct {
	Method, Path    string            `json:",omitempty"`
	Domain          string            `json:",omitempty"`
	Proto           string            `json:",omitempty"`
	Code            int               `json:",omitempty"`
	Data            interface{}       `json:",omitempty"`
	Headers         map[string]string `json:",omitempty"`
	PathParams      map[string]string `json:",omitempty"`
	Cookies         []*http.Cookie    `json:",omitempty"`
	Delay           time.Duration     `json:",omitempty"`
	BodyMatch       string            `json:",omitempty"`
	BodyMatchFunc   func([]byte) bool `json:",omitempty"`
	BodyNotMatch    string            `json:",omitempty"`
	HeadersMatch    map[string]string `json:",omitempty"`
	HeadersNotMatch map[string]string `json:",omitempty"`
	JSONMatch       map[string]string `json:",omitempty"`
	ErrorMatch      string            `json:",omitempty"`
	BeforeFn        func()            `json:"-"`
	Client          *http.Client      `json:"-"`

	AdminAuth      bool `json:",omitempty"`
	ControlRequest bool `json:",omitempty"`
}
```

`Test` provides a test runner, which generate HTTP requests based on specification and does assertions. Most of the time you going to use `tykTestServer#Run(t *testing.T, test.TestCase...) (*http.Response, error)`function. Note that it use variadic number of arguments, so if you need to pass multiple test cases, pass it  like in example above: `[]test.TestCase{<tc1>,<tc2>}...`, with 3 dots in the end.

Additionally there is `RunEx` function, with exactly same definition, but internally it runs test cases multiple times (4 right now) with different combinations of `overrideDefaults` and `hotReload` options. This can be handy if you need to test functionality that tightly depends hot reload functionality, like reloading APIs, loading plugin bundles or listener itself.

Both `Run` and `RunEx` also return response and error of the last test case, in case if you need it.
### Changing config variables
In lot of cases tests depend on various config variables. You can can update them directly on the gateway config object `Gw.GetConfig` doing:

```go
   ts := gateway.StartTest(nil)
   defer ts.Close()
    
   // Obtains current config
   currentConfig := ts.Gw.GetConfig()
   // perform changes
   currentConfig..HTTPProfile = true
   // set new config
   ts.Gw.SetConfig(currentConfig)
   // in some cases will be needed a reload
   ts.Gw.DoReload()
``` 

```go
config.Global.HttpServerOptions.OverrideDefaults = true
config.Global.HttpServerOptions.SkipURLCleaning = true
defer resetTestConfig()
```

### Upstream test server
You may notice that default API already targets some upstream mock, created for testing purpose. Url of the upstream hold in `testHttpAny` variable, but in most cases you do not need it, because APIs created by default already embed it. By default this upstream mock will successfully respond to any url, and response will contain details of the request in the following format:

```go
type testHttpResponse struct {
    Method  string
    Url     string
    Headers map[string]string
    Form    map[string]string
}
```

Note that it include final request details, so, for example if you need to test URL rewriting functionality, URL of original request will differ from URL in response of upstream mock, and you can assert it with: BodyMatch: "Url":"<assert-url>". Also notice how we used simple BodyMatch string assertion to validation JSON response. 

There is also few special URLs with specific behavior:
- `/get` accepts only `GET` requests
- `/post` accepts only `POST` requests
- `/jwk.json` used for cases when JWK token downloaded from upsteram
- `/ws` used for testing WebSockets
- `/bundles` built in plugin bundle web server, more details below

### Coprocess plugin testing
If you want use Python, Lua or GRPC plugins, you need bundle manifest file and scripts to ZIP file, upload them somewhere on external file webserver, and point Gateway to bundle location. 

Our test framework include built-in bundle file server, and for simplicity, you provide only content of the of the bundle files, and it will automatically server it as ZIP file. 
1. Create `map[string]string` object with file contents, where key is file name
2. Call `registerBundle("<unique-plugin-id>", <map-with-files>)` which will return unique bundle ID.
3. When creating API set `spec.CustomMiddlewareBundle` to bundle ID returned by `registerBundle`

Example of loading `python` auth plugin:

```go
var pythonBundleWithAuthCheck = map[string]string{
    "manifest.json": `
        {
            "file_list": [
                "middleware.py"
            ],
            "custom_middleware": {
                "driver": "python",
                "auth_check": {
                    "name": "MyAuthHook"
                }
            }
        }
    `,
    "middleware.py": `
from tyk.decorators import *
from gateway import TykGateway as tyk
@Hook
def MyAuthHook(request, session, metadata, spec):
    print("MyAuthHook is called")
    auth_header = request.get_header('Authorization')
    if auth_header == 'valid_token':
        session.rate = 1000.0
        session.per = 1.0
        metadata["token"] = "valid_token"
    return request, session, metadata
    `,
}
    
func TestPython(t *testing.T) {
     ts := gateway.StartTest(nil)
     defer ts.Close()
    
    bundleID := ts.registerBundle("python_with_auth_check", pythonBundleWithAuthCheck)

    ts.Gw.buildAndLoadAPI(func(spec *APISpec) {
        spec.UseKeylessAccess = false
        spec.EnableCoProcessAuth = true
        spec.CustomMiddlewareBundle = bundleID
    })
    // test code goes here
}
```

### Creating user sessions
You can create a user session, similar to API, by calling `createSession` function:
```go
 ts := gateway.StartTest(nil)
 defer ts.Close()

key := ts.Gw.createSession(func(s *user.SessionState) {
    s.QuotaMax = 2
})
```
You can call it without arguments as well, if you are ok with default settings `createSession()`

If you need to create session object without adding it to database, for example if you need to create key explicitly via API, you can use `createStandardSession()` function, which returns `*user.SessionState` object.

### Custom upstream mock
If you need to create custom upstream test server, for example if you need custom TLS settings for Mutual TLS testing, the easiest way is to use standard  Go `net/http/httptest` package and override `spec.Proxy.TargetURL` API URL to test server.

```go
 ts := gateway.StartTest(nil)
 defer ts.Close()

upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // custom logic
}))

ts.Gw.buildAndLoadAPI(func(spec *APISpec) {
    spec.Proxy.TargetURL = upstream.URL
})
```

### Mocking dashboard
There is no any specific object to mock the dashboard (yet), but since Dashboard is a standard HTTP server, you can use approach similar to described in **Custom upstream mock** section:

```go


dashboard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    if r.URL.Path == "/system/apis" {
        w.Write([]byte(`{"Status": "OK", "Nonce": "1", "Message": [{"api_definition": {}}]}`))
    } else {
        t.Fatal("Unknown dashboard API request", r)
    }
}))

conf := func(confi *config.Config) {
		confi.Global.UseDBAppConfigs = true
        confi.Global.AllowInsecureConfigs = true
        confi.Global.DBAppConfOptions.ConnectionString = dashboard.URL
}

ts := gateway.StartTest(conf)
defer ts.Close()
```

### Mocking RPC (Hybrid)
When Gateway works in Hybrid mode, it talks with MDCB instance via RPC channel using `gorpc` library. You can use `startRPCMock` and `stopRPCMock` functions to mock RPC server. `startRPCMock` internally sets required config variables to enable RPC mode.

```go
func TestSyncAPISpecsRPCSuccess(t *testing.T) {
    // Mock RPC
    dispatcher := gorpc.NewDispatcher()
    dispatcher.AddFunc("GetApiDefinitions", func(clientAddr string, dr *DefRequest) (string, error) {
        return "[{}]", nil
    })
    dispatcher.AddFunc("Login", func(clientAddr, userKey string) bool {
        return true
    })
    rpc := startRPCMock(dispatcher)
    defer stopRPCMock(rpc)
    count := syncAPISpecs()
    if count != 1 {
        t.Error("Should return array with one spec", apiSpecs)
    }
}
```

### DNS mocks
Inside tests we override default network resolver to use custom DNS server mock, creating using awesome `github.com/miekg/dns` library. Domain -\> IP mapping set via map inside `helpers_test.go` file. By default you have access to domains: `localhost`, `host1.local`, `host2.local` and `host3.local`. Access to all unknown domains will cause panic. 

Using DNS mock means that you are able to create tests with APIs on multiple domains, without modifying machine `/etc/hosts` file. 

## Test Framework

Usage of framework described above is not limited by Tyk Gateway, and it is used across variety of Tyk projects. 
The main building block is the test runner. 
```go
type HTTPTestRunner struct {
	Do             func(*http.Request, *TestCase) (*http.Response, error)
	Assert         func(*http.Response, *TestCase) error
	RequestBuilder func(*TestCase) (*http.Request, error)
}
func (r HTTPTestRunner) Run(t testing.TB, testCases ...TestCase) {
...
}
```
By overriding its variables, you can tune runner behavior.
For example http runner can be look like:
```
import "github.com/TykTechnologies/tyk/test"

...
baseURL := "http://example.com"
runner := test.HTTPTestRunner{
    Do: func(r *http.Request, tc *TestCase) (*http.Response, error) {
      return tc.Client.Do(r)  
    }
    RequestBuilder: func(tc *TestCase) (*http.Request, error) {
        tc.BaseURL = baseURL
        return NewRequest(tc)
    },
}
runner.Run(t, testCases...)
...
```
And Unit testing of http handlers can be:
```
import "github.com/TykTechnologies/tyk/test"

...
handler := func(wr http.RequestWriter, r *http.Request){...}
runner := test.HTTPTestRunner{
    Do: func(r *http.Request, _ *TestCase) (*http.Response, error) {
		rec := httptest.NewRecorder()
		handler(rec, r)
		return rec.Result(), nil
	},
}
runner.Run(t, testCases...)
...
```

This package already exports functions for cases mentioned above:
 - `func TestHttpServer(t testing.TB, baseURL string, testCases ...TestCase)`
 - `func TestHttpHandler(t testing.TB, handle http.HandlerFunc, testCases ...TestCase)`
