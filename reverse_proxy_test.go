package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"text/template"

	"github.com/TykTechnologies/tyk/apidef"
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
			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
			spec.URLRewriteEnabled = true

			req := testReq(t, "GET", tc.inURL, nil)
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

func TestSingleJoiningSlash(t *testing.T) {
	tests := []struct {
		a, b, want string
	}{
		{"foo", "", "foo"},
		{"foo", "bar", "foo/bar"},
		{"foo/", "bar", "foo/bar"},
		{"foo", "/bar", "foo/bar"},
		{"foo/", "/bar", "foo/bar"},
		{"foo//", "//bar", "foo/bar"},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s+%s", tc.a, tc.b), func(t *testing.T) {
			got := singleJoiningSlash(tc.a, tc.b)
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
		got := requestIP(r)
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
			r, err := http.NewRequest("GET", "http://test/test", nil)
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
