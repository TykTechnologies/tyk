// +build coprocess
// +build python

package main

import (
	"testing"

	"github.com/TykTechnologies/tyk/test"
)

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

func TestPythonBundles(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	bundleID := registerBundle("python_with_auth_check", pythonBundleWithAuthCheck)

	t.Run("Single-file bundle with authentication hook", func(t *testing.T) {
		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test-api/"
			spec.UseKeylessAccess = false
			spec.EnableCoProcessAuth = true
			spec.CustomMiddlewareBundle = bundleID
			spec.VersionData.NotVersioned = true
		})

		validAuth := map[string]string{"Authorization": "valid_token"}
		invalidAuth := map[string]string{"Authorization": "invalid_token"}

		ts.Run(t, []test.TestCase{
			{Path: "/test-api/", Code: 200, Headers: validAuth},
			{Path: "/test-api/", Code: 403, Headers: invalidAuth},
		}...)
	})
}
