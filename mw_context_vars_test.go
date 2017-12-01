package main

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
)

func TestContextVarsMiddleware(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	buildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.EnableContextVars = true
		spec.VersionData.Versions = map[string]apidef.VersionInfo{
			"v1": {
				UseExtendedPaths: true,
				GlobalHeaders: map[string]string{
					"X-Static":      "foo",
					"X-Request-ID":  "$tyk_context.request_id",
					"X-Path":        "$tyk_context.path",
					"X-Remote-Addr": "$tyk_context.remote_addr",
				},
			},
		}
	})

	ts.Run(t, []test.TestCase{
		{Path: "/test/path", Code: 200, BodyMatch: `"X-Remote-Addr":"127.0.0.1"`},
		{Path: "/test/path", Code: 200, BodyMatch: `"X-Path":"/test/path"`},
		{Path: "/test/path", Code: 200, BodyMatch: `"X-Static":"foo"`},
		{Path: "/test/path", Code: 200, BodyMatch: `"X-Request-Id":"`},
	}...)
}
