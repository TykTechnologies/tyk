package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/TykTechnologies/tyk/test"

	"github.com/TykTechnologies/tyk/dnscache"

	"github.com/TykTechnologies/tyk/config"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/request"
)

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

			req := testReq(t, http.MethodGet, tc.inURL, nil)
			req.URL.Path = tc.inPath
			if tc.retainHost {
				setCtxValue(req, RetainHost, true)
			}

			proxy := TykNewSingleHostReverseProxy(target, spec)
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
		{
			"Should cache wss protocol host dns records",
			wsHostWssApiUrl,
			http.MethodGet, nil,
			map[string][]string{
				"Upgrade":    {"websocket"},
				"Connection": {"Upgrade"},
			},
			true,
			etcHostsMap[wsHost],
			true, true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			storage := dnsCacheManager.CacheStorage()
			if !tc.isCacheEnabled {
				dnsCacheManager.SetCacheStorage(nil)
			}

			spec := &APISpec{APIDefinition: &apidef.APIDefinition{},
				EnforcedTimeoutEnabled: true,
				GlobalConfig:           config.Config{ProxyCloseConnections: true, ProxyDefaultTimeout: 1}}

			req := testReq(t, tc.Method, tc.URL, tc.Body)
			for name, value := range tc.Headers {
				req.Header.Add(name, strings.Join(value, ";"))
			}

			Url, _ := url.Parse(tc.URL)
			proxy := TykNewSingleHostReverseProxy(Url, spec)
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
	target, _ := url.Parse(testHttpGet)
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
	return TykNewSingleHostReverseProxy(target, spec)
}

func TestWrappedServeHTTP(t *testing.T) {
	proxy := testNewWrappedServeHTTP()
	recorder := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	proxy.WrappedServeHTTP(recorder, req, false)
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

			spec := createSpecTest(t, specOutput.String())
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
