// +build coprocess
// +build python

package main

import (
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
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

var pythonBundleWithPostHook = map[string]string{
	"manifest.json": `
		{
		    "file_list": [
		        "middleware.py"
		    ],
		    "custom_middleware": {
		        "driver": "python",
		        "post": [{
		            "name": "MyPostHook"
		        }]
		    }
		}
	`,
	"middleware.py": `
from tyk.decorators import *
from gateway import TykGateway as tyk
import json

@Hook
def MyPostHook(request, session, spec):
    print("called", session.metadata)
    if "testkey" not in session.metadata.keys():
        request.object.return_overrides.response_code = 400
        request.object.return_overrides.response_error = "'testkey' not found in metadata"
        return request, session
    nested_data = json.loads(session.metadata["testkey"])
    if "nestedkey" not in nested_data:
        request.object.return_overrides.response_code = 400
        request.object.return_overrides.response_error = "'nestedkey' not found in nested metadata"
        return request, session
    if "stringkey" not in session.metadata.keys():
        request.object.return_overrides.response_code = 400
        request.object.return_overrides.response_error = "'stringkey' not found in metadata"
        return request, session
    stringkey = session.metadata["stringkey"]
    if stringkey != "testvalue":
        request.object.return_overrides.response_code = 400
        request.object.return_overrides.response_error = "'stringkey' value doesn't match"
        return request, session	
    return request, session

`,
}

func TestPythonBundles(t *testing.T) {
	ts := newTykTestServer(tykTestServerConfig{
		coprocessConfig: config.CoProcessConfig{
			EnableCoProcess: true,
		}})
	defer ts.Close()

	bundleID := registerBundle("python_with_auth_check", pythonBundleWithAuthCheck)
	bundleID2 := registerBundle("python_with_post_hook", pythonBundleWithPostHook)

	t.Run("Single-file bundle with authentication hook", func(t *testing.T) {
		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test-api/"
			spec.UseKeylessAccess = false
			spec.EnableCoProcessAuth = true
			spec.CustomMiddlewareBundle = bundleID
			spec.VersionData.NotVersioned = true
		})

		time.Sleep(1 * time.Second)

		validAuth := map[string]string{"Authorization": "valid_token"}
		invalidAuth := map[string]string{"Authorization": "invalid_token"}

		ts.Run(t, []test.TestCase{
			{Path: "/test-api/", Code: 200, Headers: validAuth},
			{Path: "/test-api/", Code: 403, Headers: invalidAuth},
		}...)
	})

	t.Run("Single-file bundle with post hook", func(t *testing.T) {

		keyID := createSession(func(s *user.SessionState) {
			s.MetaData = map[string]interface{}{
				"testkey":   map[string]interface{}{"nestedkey": "nestedvalue"},
				"stringkey": "testvalue",
			}
		})

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test-api-2/"
			spec.UseKeylessAccess = false
			spec.EnableCoProcessAuth = false
			spec.CustomMiddlewareBundle = bundleID2
			spec.VersionData.NotVersioned = true
		})

		time.Sleep(1 * time.Second)

		auth := map[string]string{"Authorization": keyID}

		ts.Run(t, []test.TestCase{
			{Path: "/test-api-2/", Code: 200, Headers: auth},
		}...)
	})
}
