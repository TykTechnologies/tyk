package main

import (
	"net/url"
	"testing"

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
