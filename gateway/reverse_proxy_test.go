package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/jensneuse/graphql-go-tools/pkg/execution/datasource"
	"github.com/jensneuse/graphql-go-tools/pkg/graphql"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/dnscache"
	"github.com/TykTechnologies/tyk/request"
	"github.com/TykTechnologies/tyk/test"
)

func TestCopyHeader_NoDuplicateCORSHeaders(t *testing.T) {

	makeHeaders := func(withCORS bool) http.Header {

		var h = http.Header{}

		h.Set("Vary", "Origin")
		h.Set("Location", "https://tyk.io")

		if withCORS {
			for _, v := range corsHeaders {
				h.Set(v, "tyk.io")
			}
		}

		return h
	}

	tests := []struct {
		src, dst http.Header
	}{
		{makeHeaders(true), makeHeaders(false)},
		{makeHeaders(true), makeHeaders(true)},
		{makeHeaders(false), makeHeaders(true)},
	}

	for _, v := range tests {
		copyHeader(v.dst, v.src, false)

		for _, vv := range corsHeaders {
			val := v.dst[vv]
			if n := len(val); n != 1 {
				t.Fatalf("%s found %d times", vv, n)
			}

		}

	}
}

func TestReverseProxyRetainHost(t *testing.T) {
	target, _ := url.Parse("http://target-host.com/targetpath")
	cases := []struct {
		name          string
		inURL, inPath string
		retainHost    bool
		wantURL       string
	}{
		{
			"no-retain-same-path",
			"http://orig-host.com/origpath", "/origpath",
			false, "http://target-host.com/targetpath/origpath",
		},
		{
			"no-retain-minus-slash",
			"http://orig-host.com/origpath", "origpath",
			false, "http://target-host.com/targetpath/origpath",
		},
		{
			"retain-same-path",
			"http://orig-host.com/origpath", "/origpath",
			true, "http://orig-host.com/origpath",
		},
		{
			"retain-minus-slash",
			"http://orig-host.com/origpath", "origpath",
			true, "http://orig-host.com/origpath",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}, URLRewriteEnabled: true}
			spec.URLRewriteEnabled = true

			req := TestReq(t, http.MethodGet, tc.inURL, nil)
			req.URL.Path = tc.inPath
			if tc.retainHost {
				setCtxValue(req, ctx.RetainHost, true)
			}

			proxy := TykNewSingleHostReverseProxy(target, spec, nil)
			proxy.Director(req)

			if got := req.URL.String(); got != tc.wantURL {
				t.Fatalf("wanted url %q, got %q", tc.wantURL, got)
			}
		})
	}
}

type configTestReverseProxyDnsCache struct {
	*testing.T

	etcHostsMap map[string][]string
	dnsConfig   config.DnsCacheConfig
}

func setupTestReverseProxyDnsCache(cfg *configTestReverseProxyDnsCache) func() {
	pullDomains := mockHandle.PushDomains(cfg.etcHostsMap, nil)
	dnsCacheManager.InitDNSCaching(
		time.Duration(cfg.dnsConfig.TTL)*time.Second, time.Duration(cfg.dnsConfig.CheckInterval)*time.Second)

	globalConf := config.Global()
	enableWebSockets := globalConf.HttpServerOptions.EnableWebSockets

	globalConf.HttpServerOptions.EnableWebSockets = true
	config.SetGlobal(globalConf)

	return func() {
		pullDomains()
		dnsCacheManager.DisposeCache()
		globalConf.HttpServerOptions.EnableWebSockets = enableWebSockets
		config.SetGlobal(globalConf)
	}
}

func TestReverseProxyDnsCache(t *testing.T) {
	const (
		host   = "orig-host.com."
		host2  = "orig-host2.com."
		host3  = "orig-host3.com."
		wsHost = "ws.orig-host.com."

		hostApiUrl       = "http://orig-host.com/origpath"
		host2HttpApiUrl  = "http://orig-host2.com/origpath"
		host2HttpsApiUrl = "https://orig-host2.com/origpath"
		host3ApiUrl      = "https://orig-host3.com/origpath"
		wsHostWsApiUrl   = "ws://ws.orig-host.com/connect"
		wsHostWssApiUrl  = "wss://ws.orig-host.com/connect"

		cacheTTL            = 5
		cacheUpdateInterval = 10
	)

	var (
		etcHostsMap = map[string][]string{
			host:   {"127.0.0.10", "127.0.0.20"},
			host2:  {"10.0.20.0", "10.0.20.1", "10.0.20.2"},
			host3:  {"10.0.20.15", "10.0.20.16"},
			wsHost: {"127.0.0.10", "127.0.0.10"},
		}
	)

	tearDown := setupTestReverseProxyDnsCache(&configTestReverseProxyDnsCache{t, etcHostsMap,
		config.DnsCacheConfig{
			Enabled: true, TTL: cacheTTL, CheckInterval: cacheUpdateInterval,
			MultipleIPsHandleStrategy: config.NoCacheStrategy}})

	currentStorage := dnsCacheManager.CacheStorage()
	fakeDeleteStorage := &dnscache.MockStorage{
		MockFetchItem: currentStorage.FetchItem,
		MockGet:       currentStorage.Get,
		MockSet:       currentStorage.Set,
		MockDelete: func(key string) {
			//prevent deletion
		},
		MockClear: currentStorage.Clear}
	dnsCacheManager.SetCacheStorage(fakeDeleteStorage)

	defer tearDown()

	cases := []struct {
		name string

		URL     string
		Method  string
		Body    []byte
		Headers http.Header

		isWebsocket bool

		expectedIPs    []string
		shouldBeCached bool
		isCacheEnabled bool
	}{
		{
			"Should cache first request to Host1",
			hostApiUrl,
			http.MethodGet, nil, nil,
			false,
			etcHostsMap[host],
			true, true,
		},
		{
			"Should cache first request to Host2",
			host2HttpsApiUrl,
			http.MethodPost, []byte("{ \"param\": \"value\" }"), nil,
			false,
			etcHostsMap[host2],
			true, true,
		},
		{
			"Should populate from cache second request to Host1",
			hostApiUrl,
			http.MethodGet, nil, nil,
			false,
			etcHostsMap[host],
			false, true,
		},
		{
			"Should populate from cache second request to Host2 with different protocol",
			host2HttpApiUrl,
			http.MethodPost, []byte("{ \"param\": \"value2\" }"), nil,
			false,
			etcHostsMap[host2],
			false, true,
		},
		{
			"Shouldn't cache request with different http verb to same host",
			hostApiUrl,
			http.MethodPatch, []byte("{ \"param2\": \"value3\" }"), nil,
			false,
			etcHostsMap[host],
			false, true,
		},
		{
			"Shouldn't cache dns record when cache is disabled",
			host3ApiUrl,
			http.MethodGet, nil, nil,
			false, etcHostsMap[host3],
			false, false,
		},
		{
			"Should cache ws protocol host dns records",
			wsHostWsApiUrl,
			http.MethodGet, nil,
			map[string][]string{
				"Upgrade":    {"websocket"},
				"Connection": {"Upgrade"},
			},
			true,
			etcHostsMap[wsHost],
			true, true,
		},
		// {
		// 	"Should cache wss protocol host dns records",
		// 	wsHostWssApiUrl,
		// 	http.MethodGet, nil,
		// 	map[string][]string{
		// 		"Upgrade":    {"websocket"},
		// 		"Connection": {"Upgrade"},
		// 	},
		// 	true,
		// 	etcHostsMap[wsHost],
		// 	true, true,
		// },
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			storage := dnsCacheManager.CacheStorage()
			if !tc.isCacheEnabled {
				dnsCacheManager.SetCacheStorage(nil)
			}

			spec := &APISpec{APIDefinition: &apidef.APIDefinition{},
				EnforcedTimeoutEnabled: true,
				GlobalConfig:           config.Config{ProxyCloseConnections: true, ProxyDefaultTimeout: 0.1}}

			req := TestReq(t, tc.Method, tc.URL, tc.Body)
			for name, value := range tc.Headers {
				req.Header.Add(name, strings.Join(value, ";"))
			}

			Url, _ := url.Parse(tc.URL)
			proxy := TykNewSingleHostReverseProxy(Url, spec, nil)
			recorder := httptest.NewRecorder()
			proxy.WrappedServeHTTP(recorder, req, false)

			host := Url.Hostname()
			if tc.isCacheEnabled {
				item, ok := storage.Get(host)
				if !ok || !test.IsDnsRecordsAddrsEqualsTo(item.Addrs, tc.expectedIPs) {
					t.Fatalf("got %q, but wanted %q. ok=%t", item, tc.expectedIPs, ok)
				}
			} else {
				item, ok := storage.Get(host)
				if ok {
					t.Fatalf("got %t, but wanted %t. item=%#v", ok, false, item)
				}
			}

			if !tc.isCacheEnabled {
				dnsCacheManager.SetCacheStorage(storage)
			}
		})
	}
}

func testNewWrappedServeHTTP() *ReverseProxy {
	target, _ := url.Parse(TestHttpGet)
	def := apidef.APIDefinition{}
	def.VersionData.DefaultVersion = "Default"
	def.VersionData.Versions = map[string]apidef.VersionInfo{
		"Default": {
			Name:             "v2",
			UseExtendedPaths: true,
			ExtendedPaths: apidef.ExtendedPathsSet{
				TransformHeader: []apidef.HeaderInjectionMeta{
					{
						DeleteHeaders: []string{"header"},
						AddHeaders:    map[string]string{"newheader": "newvalue"},
						Path:          "/abc",
						Method:        "GET",
						ActOnResponse: true,
					},
				},
				URLRewrite: []apidef.URLRewriteMeta{
					{
						Path:         "/get",
						Method:       "GET",
						MatchPattern: "/get",
						RewriteTo:    "/post",
					},
				},
			},
		},
	}
	spec := &APISpec{
		APIDefinition:          &def,
		EnforcedTimeoutEnabled: true,
		CircuitBreakerEnabled:  true,
	}
	return TykNewSingleHostReverseProxy(target, spec, nil)
}

func TestWrappedServeHTTP(t *testing.T) {
	proxy := testNewWrappedServeHTTP()
	recorder := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	proxy.WrappedServeHTTP(recorder, req, false)
}

func TestCircuitBreaker5xxs(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	t.Run("Extended Paths", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				json.Unmarshal([]byte(`[
					{
						"path": "error",
						"method": "GET",
						"threshold_percent": 0.1,
						"samples": 3,
						"return_to_service_after": 6000
					}
  			 	]`), &v.ExtendedPaths.CircuitBreaker)
			})
			spec.Proxy.ListenPath = "/"
			spec.CircuitBreakerEnabled = true
		})

		ts.Run(t, []test.TestCase{
			{Path: "/errors/500", Code: http.StatusInternalServerError},
			{Path: "/errors/501", Code: http.StatusNotImplemented},
			{Path: "/errors/502", Code: http.StatusBadGateway},
			{Path: "/errors/500", Code: http.StatusServiceUnavailable},
			{Path: "/errors/501", Code: http.StatusServiceUnavailable},
			{Path: "/errors/502", Code: http.StatusServiceUnavailable},
		}...)
	})
}

func TestSingleJoiningSlash(t *testing.T) {
	testsFalse := []struct {
		a, b, want string
	}{
		{"foo", "", "foo"},
		{"foo", "bar", "foo/bar"},
		{"foo/", "bar", "foo/bar"},
		{"foo", "/bar", "foo/bar"},
		{"foo/", "/bar", "foo/bar"},
		{"foo//", "//bar", "foo/bar"},
	}
	for _, tc := range testsFalse {
		t.Run(fmt.Sprintf("%s+%s", tc.a, tc.b), func(t *testing.T) {
			got := singleJoiningSlash(tc.a, tc.b, false)
			if got != tc.want {
				t.Fatalf("want %s, got %s", tc.want, got)
			}
		})
	}
	testsTrue := []struct {
		a, b, want string
	}{
		{"foo/", "", "foo/"},
		{"foo", "", "foo"},
	}
	for _, tc := range testsTrue {
		t.Run(fmt.Sprintf("%s+%s", tc.a, tc.b), func(t *testing.T) {
			got := singleJoiningSlash(tc.a, tc.b, true)
			if got != tc.want {
				t.Fatalf("want %s, got %s", tc.want, got)
			}
		})
	}
}

func TestRequestIP(t *testing.T) {
	tests := []struct {
		remote, real, forwarded, want string
	}{
		// missing ip or port
		{want: ""},
		{remote: ":80", want: ""},
		{remote: "1.2.3.4", want: ""},
		{remote: "[::1]", want: ""},
		// no headers
		{remote: "1.2.3.4:80", want: "1.2.3.4"},
		{remote: "[::1]:80", want: "::1"},
		// real-ip
		{
			remote: "1.2.3.4:80",
			real:   "5.6.7.8",
			want:   "5.6.7.8",
		},
		{
			remote: "[::1]:80",
			real:   "::2",
			want:   "::2",
		},
		// forwarded-for
		{
			remote:    "1.2.3.4:80",
			forwarded: "5.6.7.8, px1, px2",
			want:      "5.6.7.8",
		},
		{
			remote:    "[::1]:80",
			forwarded: "::2",
			want:      "::2",
		},
		// both real-ip and forwarded-for
		{
			remote:    "1.2.3.4:80",
			real:      "5.6.7.8",
			forwarded: "4.3.2.1, px1, px2",
			want:      "5.6.7.8",
		},
	}
	for _, tc := range tests {
		r := &http.Request{RemoteAddr: tc.remote, Header: http.Header{}}
		r.Header.Set("x-real-ip", tc.real)
		r.Header.Set("x-forwarded-for", tc.forwarded)
		got := request.RealIP(r)
		if got != tc.want {
			t.Errorf("requestIP({%q, %q, %q}) got %q, want %q",
				tc.remote, tc.real, tc.forwarded, got, tc.want)
		}
	}
}

func TestCheckHeaderInRemoveList(t *testing.T) {
	type testSpec struct {
		UseExtendedPaths      bool
		GlobalHeadersRemove   []string
		ExtendedDeleteHeaders []string
	}
	tpl, err := template.New("test_tpl").Parse(`{
		"api_id": "1",
		"version_data": {
			"not_versioned": true,
			"versions": {
				"Default": {
					"name": "Default",
					"use_extended_paths": {{ .UseExtendedPaths }},
					"global_headers_remove": [{{ range $index, $hdr := .GlobalHeadersRemove }}{{if $index}}, {{end}}{{print "\"" . "\"" }}{{end}}],
					"extended_paths": {
						"transform_headers": [{
							"delete_headers": [{{range $index, $hdr := .ExtendedDeleteHeaders}}{{if $index}}, {{end}}{{print "\"" . "\""}}{{end}}],
							"path": "test",
							"method": "GET"
						}]
					}
				}
			}
		}
	}`)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		header   string
		spec     testSpec
		expected bool
	}{
		{
			header: "X-Forwarded-For",
		},
		{
			header: "X-Forwarded-For",
			spec:   testSpec{GlobalHeadersRemove: []string{"X-Random-Header"}},
		},
		{
			header: "X-Forwarded-For",
			spec: testSpec{
				UseExtendedPaths:      true,
				ExtendedDeleteHeaders: []string{"X-Random-Header"},
			},
		},
		{
			header:   "X-Forwarded-For",
			spec:     testSpec{GlobalHeadersRemove: []string{"X-Forwarded-For"}},
			expected: true,
		},
		{
			header: "X-Forwarded-For",
			spec: testSpec{
				UseExtendedPaths:      true,
				GlobalHeadersRemove:   []string{"X-Random-Header"},
				ExtendedDeleteHeaders: []string{"X-Forwarded-For"},
			},
			expected: true,
		},
		{
			header: "X-Forwarded-For",
			spec: testSpec{
				UseExtendedPaths:      true,
				GlobalHeadersRemove:   []string{"X-Forwarded-For"},
				ExtendedDeleteHeaders: []string{"X-Forwarded-For"},
			},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s:%t", tc.header, tc.expected), func(t *testing.T) {
			rp := &ReverseProxy{}
			r, err := http.NewRequest(http.MethodGet, "http://test/test", nil)
			if err != nil {
				t.Fatal(err)
			}

			var specOutput bytes.Buffer
			if err := tpl.Execute(&specOutput, tc.spec); err != nil {
				t.Fatal(err)
			}

			spec := LoadSampleAPI(specOutput.String())
			actual := rp.CheckHeaderInRemoveList(tc.header, spec, r)
			if actual != tc.expected {
				t.Fatalf("want %t, got %t", tc.expected, actual)
			}
		})
	}
}

func testRequestIPHops(t testing.TB) {
	req := &http.Request{
		Header:     http.Header{},
		RemoteAddr: "test.com:80",
	}
	req.Header.Set("X-Forwarded-For", "abc")
	match := "abc, test.com"
	clientIP := requestIPHops(req)
	if clientIP != match {
		t.Fatalf("Got %s, expected %s", clientIP, match)
	}
}

func TestRequestIPHops(t *testing.T) {
	testRequestIPHops(t)
}

func TestNopCloseRequestBody(t *testing.T) {
	// try to pass nil request
	var req *http.Request
	nopCloseRequestBody(req)
	if req != nil {
		t.Error("nil Request should remain nil")
	}

	// try to pass nil body
	req = &http.Request{}
	nopCloseRequestBody(req)
	if req.Body != nil {
		t.Error("Request nil body should remain nil")
	}

	// try to pass not nil body and check that it was replaced with nopCloser
	req = httptest.NewRequest(http.MethodGet, "/test", strings.NewReader("abcxyz"))
	nopCloseRequestBody(req)
	if body, ok := req.Body.(nopCloser); !ok {
		t.Error("Request's body was not replaced with nopCloser")
	} else {
		// try to read body 1st time
		if data, err := ioutil.ReadAll(body); err != nil {
			t.Error("1st read, error while reading body:", err)
		} else if !bytes.Equal(data, []byte("abcxyz")) { // compare with expected data
			t.Error("1st read, body's data is not as expectd")
		}

		// try to read body again without closing
		if data, err := ioutil.ReadAll(body); err != nil {
			t.Error("2nd read, error while reading body:", err)
		} else if !bytes.Equal(data, []byte("abcxyz")) { // compare with expected data
			t.Error("2nd read, body's data is not as expectd")
		}

		// close body and try to read "closed" one
		body.Close()
		if data, err := ioutil.ReadAll(body); err != nil {
			t.Error("3rd read, error while reading body:", err)
		} else if !bytes.Equal(data, []byte("abcxyz")) { // compare with expected data
			t.Error("3rd read, body's data is not as expectd")
		}
	}
}

func TestNopCloseResponseBody(t *testing.T) {
	var resp *http.Response
	nopCloseResponseBody(resp)
	if resp != nil {
		t.Error("nil Response should remain nil")
	}

	// try to pass nil body
	resp = &http.Response{}
	nopCloseResponseBody(resp)
	if resp.Body != nil {
		t.Error("Response nil body should remain nil")
	}

	// try to pass not nil body and check that it was replaced with nopCloser
	resp = &http.Response{}
	resp.Body = ioutil.NopCloser(strings.NewReader("abcxyz"))
	nopCloseResponseBody(resp)
	if body, ok := resp.Body.(nopCloser); !ok {
		t.Error("Response's body was not replaced with nopCloser")
	} else {
		// try to read body 1st time
		if data, err := ioutil.ReadAll(body); err != nil {
			t.Error("1st read, error while reading body:", err)
		} else if !bytes.Equal(data, []byte("abcxyz")) { // compare with expected data
			t.Error("1st read, body's data is not as expectd")
		}

		// try to read body again without closing
		if data, err := ioutil.ReadAll(body); err != nil {
			t.Error("2nd read, error while reading body:", err)
		} else if !bytes.Equal(data, []byte("abcxyz")) { // compare with expected data
			t.Error("2nd read, body's data is not as expectd")
		}

		// close body and try to read "closed" one
		body.Close()
		if data, err := ioutil.ReadAll(body); err != nil {
			t.Error("3rd read, error while reading body:", err)
		} else if !bytes.Equal(data, []byte("abcxyz")) { // compare with expected data
			t.Error("3rd read, body's data is not as expectd")
		}
	}
}

func TestGraphQL_HeadersInjection(t *testing.T) {
	g := StartTest()
	t.Cleanup(g.Close)

	composedAPI := BuildAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		spec.GraphQL.Version = apidef.GraphQLConfigVersion2

		spec.GraphQL.Engine.DataSources = []apidef.GraphQLEngineDataSource{
			generateRESTDataSourceV2(func(ds *apidef.GraphQLEngineDataSource, restConfig *apidef.GraphQLEngineDataSourceConfigREST) {
				require.NoError(t, json.Unmarshal([]byte(testRESTHeadersDataSourceConfigurationV2), ds))
				require.NoError(t, json.Unmarshal(ds.Config, restConfig))
			}),
		}

		spec.GraphQL.TypeFieldConfigurations = nil
	})[0]

	LoadAPI(composedAPI)

	headers := graphql.Request{
		Query: "query Query { headers { name value } }",
	}

	_, _ = g.Run(t, []test.TestCase{
		{
			Data:    headers,
			Headers: map[string]string{"injected": "FOO"},
			Code:    http.StatusOK,

			BodyMatchFunc: func(b []byte) bool {
				return strings.Contains(string(b), `"headers":`) &&
					strings.Contains(string(b), `{"name":"Injected","value":"FOO"}`) &&
					strings.Contains(string(b), `{"name":"Static","value":"barbaz"}`)
			},
		},
	}...)
}

func TestGraphQL_InternalDataSource(t *testing.T) {
	g := StartTest()
	defer g.Close()

	tykGraphQL := BuildAPI(func(spec *APISpec) {
		spec.Name = "tyk-graphql"
		spec.APIID = "test1"
		spec.Proxy.TargetURL = testGraphQLDataSource
		spec.Proxy.ListenPath = "/tyk-graphql"
	})[0]

	tykREST := BuildAPI(func(spec *APISpec) {
		spec.Name = "tyk-rest"
		spec.APIID = "test2"
		spec.Proxy.TargetURL = testRESTDataSource
		spec.Proxy.ListenPath = "/tyk-rest"
	})[0]

	t.Run("graphql engine v2", func(t *testing.T) {
		composedAPI := BuildAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.APIID = "test3"
			spec.GraphQL.Enabled = true
			spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
			spec.GraphQL.Version = apidef.GraphQLConfigVersion2
			spec.GraphQL.Engine.DataSources[0] = generateRESTDataSourceV2(func(_ *apidef.GraphQLEngineDataSource, restConfig *apidef.GraphQLEngineDataSourceConfigREST) {
				restConfig.URL = fmt.Sprintf("tyk://%s", tykREST.Name)
			})
			spec.GraphQL.Engine.DataSources[1] = generateGraphQLDataSourceV2(func(_ *apidef.GraphQLEngineDataSource, graphqlConf *apidef.GraphQLEngineDataSourceConfigGraphQL) {
				graphqlConf.URL = fmt.Sprintf("tyk://%s", tykGraphQL.Name)
			})
			spec.GraphQL.TypeFieldConfigurations = nil
		})[0]

		LoadAPI(tykGraphQL, tykREST, composedAPI)

		countries := graphql.Request{
			Query: "query Query { countries { name } }",
		}

		people := graphql.Request{
			Query: "query Query { people { name } }",
		}

		_, _ = g.Run(t, []test.TestCase{
			// GraphQL Data Source
			{Data: countries, BodyMatch: `"countries":.*{"name":"Turkey"},{"name":"Russia"}.*`, Code: http.StatusOK},

			// REST Data Source
			{Data: people, BodyMatch: `"people":.*{"name":"Furkan"},{"name":"Leo"}.*`, Code: http.StatusOK},
		}...)
	})

	t.Run("graphql engine v1", func(t *testing.T) {
		composedAPI := BuildAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.APIID = "test4"
			spec.GraphQL.Enabled = true
			spec.GraphQL.TypeFieldConfigurations[0].DataSource.Config = generateGraphQLDataSource(func(graphQLDataSource *datasource.GraphQLDataSourceConfig) {
				graphQLDataSource.URL = fmt.Sprintf("tyk://%s", tykGraphQL.Name)
			})
			spec.GraphQL.TypeFieldConfigurations[1].DataSource.Config = generateRESTDataSource(func(restDataSource *datasource.HttpJsonDataSourceConfig) {
				restDataSource.URL = fmt.Sprintf("tyk://%s", tykREST.Name)
			})
		})[0]

		LoadAPI(tykGraphQL, tykREST, composedAPI)

		countries := graphql.Request{
			Query: "query Query { countries { name } }",
		}

		people := graphql.Request{
			Query: "query Query { people { name } }",
		}

		_, _ = g.Run(t, []test.TestCase{
			// GraphQL Data Source
			{Data: countries, BodyMatch: `"countries":.*{"name":"Turkey"},{"name":"Russia"}.*`, Code: http.StatusOK},

			// REST Data Source
			{Data: people, BodyMatch: `"people":.*{"name":"Furkan"},{"name":"Leo"}.*`, Code: http.StatusOK},
		}...)
	})
}

func TestGraphQL_ProxyIntrospectionInterrupt(t *testing.T) {
	g := StartTest()
	defer g.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
		spec.GraphQL.Schema = "schema { query: query_root } type query_root { hello: String }"
		spec.Proxy.ListenPath = "/"
	})

	t.Run("introspection request should be interrupted", func(t *testing.T) {
		namedIntrospection := graphql.Request{
			OperationName: "IntrospectionQuery",
			Query:         gqlIntrospectionQuery,
		}

		silentIntrospection := graphql.Request{
			OperationName: "",
			Query:         strings.Replace(gqlIntrospectionQuery, "query IntrospectionQuery ", "", 1),
		}

		_, _ = g.Run(t, []test.TestCase{
			{Data: namedIntrospection, BodyMatch: `"name":"query_root"`, Code: http.StatusOK},
			{Data: silentIntrospection, BodyMatch: `"name":"query_root"`, Code: http.StatusOK},
		}...)
	})

	t.Run("normal requests should be proxied", func(t *testing.T) {
		validRequest := graphql.Request{
			Query: "query { hello }",
		}

		_, _ = g.Run(t, []test.TestCase{
			{Data: validRequest, BodyMatch: `"Headers":{"Accept-Encoding"`, Code: http.StatusOK},
		}...)
	})
}

func BenchmarkRequestIPHops(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		testRequestIPHops(b)
	}
}

func BenchmarkWrappedServeHTTP(b *testing.B) {
	b.ReportAllocs()
	proxy := testNewWrappedServeHTTP()
	recorder := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	for i := 0; i < b.N; i++ {
		proxy.WrappedServeHTTP(recorder, req, false)
	}
}

func BenchmarkCopyRequestResponse(b *testing.B) {
	b.ReportAllocs()

	str := strings.Repeat("very long body line that is repeated", 128)
	req := &http.Request{}
	res := &http.Response{}
	for i := 0; i < b.N; i++ {
		req.Body = ioutil.NopCloser(strings.NewReader(str))
		res.Body = ioutil.NopCloser(strings.NewReader(str))
		for j := 0; j < 10; j++ {
			req = copyRequest(req)
			res = copyResponse(res)
		}
	}
}

func TestEnsureTransport(t *testing.T) {
	cases := []struct {
		host, protocol, expect string
	}{
		{"https://httpbin.org ", "https", "https://httpbin.org"},
		{"httpbin.org ", "https", "https://httpbin.org"},
		{"http://httpbin.org ", "https", "http://httpbin.org"},
		{"httpbin.org ", "tls", "tls://httpbin.org"},
		{"httpbin.org ", "", "http://httpbin.org"},
	}
	for i, v := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			g := EnsureTransport(v.host, v.protocol)
			if g != v.expect {
				t.Errorf("expected %q got %q", v.expect, g)
			}
		})
	}
}

func TestReverseProxyWebSocketCancelation(t *testing.T) {
	c := config.Global()
	c.HttpServerOptions.EnableWebSockets = true
	config.SetGlobal(c)
	n := 5
	triggerCancelCh := make(chan bool, n)
	nthResponse := func(i int) string {
		return fmt.Sprintf("backend response #%d\n", i)
	}
	terminalMsg := "final message"

	cst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g, ws := upgradeType(r.Header), "websocket"; g != ws {
			t.Errorf("Unexpected upgrade type %q, want %q", g, ws)
			http.Error(w, "Unexpected request", 400)
			return
		}
		conn, bufrw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()

		upgradeMsg := "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: WebSocket\r\n\r\n"
		if _, err := io.WriteString(conn, upgradeMsg); err != nil {
			t.Error(err)
			return
		}
		if _, _, err := bufrw.ReadLine(); err != nil {
			t.Errorf("Failed to read line from client: %v", err)
			return
		}

		for i := 0; i < n; i++ {
			if _, err := bufrw.WriteString(nthResponse(i)); err != nil {
				select {
				case <-triggerCancelCh:
				default:
					t.Errorf("Writing response #%d failed: %v", i, err)
				}
				return
			}
			bufrw.Flush()
			time.Sleep(time.Second)
		}
		if _, err := bufrw.WriteString(terminalMsg); err != nil {
			select {
			case <-triggerCancelCh:
			default:
				t.Errorf("Failed to write terminal message: %v", err)
			}
		}
		bufrw.Flush()
	}))
	defer cst.Close()

	backendURL, _ := url.Parse(cst.URL)
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	rproxy := TykNewSingleHostReverseProxy(backendURL, spec, nil)

	handler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("X-Header", "X-Value")
		ctx, cancel := context.WithCancel(req.Context())
		go func() {
			<-triggerCancelCh
			cancel()
		}()
		rproxy.ServeHTTP(rw, req.WithContext(ctx))
	})

	frontendProxy := httptest.NewServer(handler)
	defer frontendProxy.Close()

	req, _ := http.NewRequest("GET", frontendProxy.URL, nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res, err := frontendProxy.Client().Do(req)
	if err != nil {
		t.Fatalf("Dialing to frontend proxy: %v", err)
	}
	defer res.Body.Close()
	if g, w := res.StatusCode, 101; g != w {
		t.Fatalf("Switching protocols failed, got: %d, want: %d", g, w)
	}

	if g, w := res.Header.Get("X-Header"), "X-Value"; g != w {
		t.Errorf("X-Header mismatch\n\tgot:  %q\n\twant: %q", g, w)
	}

	if g, w := upgradeType(res.Header), "websocket"; g != w {
		t.Fatalf("Upgrade header mismatch\n\tgot:  %q\n\twant: %q", g, w)
	}

	rwc, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatalf("Response body type mismatch, got %T, want io.ReadWriteCloser", res.Body)
	}

	if _, err := io.WriteString(rwc, "Hello\n"); err != nil {
		t.Fatalf("Failed to write first message: %v", err)
	}

	// Read loop.

	br := bufio.NewReader(rwc)
	for {
		line, err := br.ReadString('\n')
		switch {
		case line == terminalMsg: // this case before "err == io.EOF"
			t.Fatalf("The websocket request was not canceled, unfortunately!")

		case err == io.EOF:
			return

		case err != nil:
			t.Fatalf("Unexpected error: %v", err)

		case line == nthResponse(0): // We've gotten the first response back
			// Let's trigger a cancel.
			close(triggerCancelCh)
		}
	}
}
