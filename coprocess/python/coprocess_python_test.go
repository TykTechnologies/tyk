package python

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func pkgPath() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Dir(filename) + "./../../"
}

var pythonBundleWithAuthCheck = func(token1, token2 string) map[string]string {
	middleware := `
from tyk.decorators import *
from gateway import TykGateway as tyk

@Hook
def MyAuthHook(request, session, metadata, spec):
  auth_header = request.get_header('Authorization')
  if auth_header == 'valid_token':
    session.rate = 1000.0
    session.per = 1.0
    session.max_query_depth = 1
    session.quota_max = 1
    session.quota_renewal_rate = 60
    metadata["token"] = "valid_token"
  if auth_header == 'token_without_quota':
    policy_id = request.get_header('Policy')
    session.apply_policy_id = policy_id
    metadata["token"] = "token_without_quota"
  return request, session, metadata
`

	middleware = strings.ReplaceAll(middleware, "valid_token", token1)
	middleware = strings.ReplaceAll(middleware, "token_without_quota", token2)
	checksum := fmt.Sprintf("%x", md5.Sum([]byte(middleware)))

	return map[string]string{
		"manifest.json": fmt.Sprintf(`
		{
		    "file_list": [
		        "middleware.py"
		    ],
		    "custom_middleware": {
		        "driver": "python",
		        "auth_check": {
		            "name": "MyAuthHook",
					"path": "middleware.py"
		        }
		    },
		    "checksum": "%s"
		}`, checksum),
		"middleware.py": middleware,
	}
}

var pythonBundleWithPostHook = func() map[string]string {
	middleware := `
from tyk.decorators import *
from gateway import TykGateway as tyk
import json

@Hook
def MyPostHook(request, session, spec):
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
`
	checksum := fmt.Sprintf("%x", md5.Sum([]byte(middleware)))
	return map[string]string{
		`manifest.json`: fmt.Sprintf(`{
		    "file_list": [
		        "middleware.py"
		    ],
		    "custom_middleware": {
		        "driver": "python",
		        "post": [{
		            "name": "MyPostHook"
		        }]
		    },
			"checksum": "%s"
		}`, checksum),
		"middleware.py": middleware,
	}
}

var pythonPostRequestTransform = func() map[string]string {
	middleware := `
from tyk.decorators import *
from gateway import TykGateway as tyk
import json

@Hook
def MyPostHook(request, session, spec):
	if request.object.url == "/test2":
		if request.object.method != "POST":
			request.object.return_overrides.response_code = 500
			request.object.return_overrides.response_error = "'invalid method type'"
			return request, session
		request.object.url = "tyk://test-api-2/newpath"
		request.object.method = "GET"

	return request , session
`
	checksum := fmt.Sprintf("%x", md5.Sum([]byte(middleware)))
	return map[string]string{
		`manifest.json`: fmt.Sprintf(`{
		    "file_list": [
		        "middleware.py"
		    ],
		    "custom_middleware": {
		        "driver": "python",
		        "post": [{
		            "name": "MyPostHook"
		        }]
		    },
			"checksum": "%s"
		}`, checksum),
		"middleware.py": middleware,
	}
}

var pythonBundleWithPreHook = func() map[string]string {
	middleware := `
from tyk.decorators import *
from gateway import TykGateway as tyk

@Hook
def MyPreHook(request, session, metadata, spec):
    content_type = request.get_header("Content-Type")
    if "json" in content_type:
      if len(request.object.raw_body) <= 0:
        request.object.return_overrides.response_code = 400
        request.object.return_overrides.response_error = "Raw body field is empty"
        return request, session, metadata
      if "{}" not in request.object.body:
        request.object.return_overrides.response_code = 400
        request.object.return_overrides.response_error = "Body field doesn't match"
        return request, session, metadata
    if "multipart" in content_type:
      if len(request.object.body) != 0:
        request.object.return_overrides.response_code = 400
        request.object.return_overrides.response_error = "Body field isn't empty"
      if len(request.object.raw_body) <= 0:
        request.object.return_overrides.response_code = 400
        request.object.return_overrides.response_error = "Raw body field is empty"
    return request, session, metadata
`
	checksum := fmt.Sprintf("%x", md5.Sum([]byte(middleware)))
	return map[string]string{
		`manifest.json`: fmt.Sprintf(`{
		    "file_list": [
		        "middleware.py"
		    ],
		    "custom_middleware": {
		        "driver": "python",
		        "pre": [{
		            "name": "MyPreHook"
		        }]
		    },
			"checksum": "%s"
		}`, checksum),
		"middleware.py": middleware,
	}
}

var pythonBundleWithResponseHook = func() map[string]string {
	middleware := `
from tyk.decorators import *
from gateway import TykGateway as tyk

@Hook
def MyResponseHook(request, response, session, metadata, spec):
  response.raw_body = b'newbody'
  return response
`
	checksum := fmt.Sprintf("%x", md5.Sum([]byte(middleware)))
	return map[string]string{
		`manifest.json`: fmt.Sprintf(`
		{
		    "file_list": [
		        "middleware.py"
		    ],
		    "custom_middleware": {
		        "driver": "python",
		        "response": [{
		            "name": "MyResponseHook"
		        }]
		    },
			"checksum": "%s"
		}
`, checksum),
		"middleware.py": middleware,
	}
}

func TestMain(m *testing.M) {
	os.Exit(gateway.InitTestMain(context.Background(), m))
}

func setupGateway() *gateway.Test {
	ts := gateway.StartTest(nil, gateway.TestConfig{
		CoprocessConfig: config.CoProcessConfig{
			EnableCoProcess:  true,
			PythonPathPrefix: pkgPath(),
		}})

	return ts
}

func TestPythonBundles(t *testing.T) {
	unused := uuid.NewHex()

	t.Run("Single-file bundle with authentication hook", func(t *testing.T) {
		ts := setupGateway()
		defer ts.Close()

		validToken := uuid.NewHex()
		authCheckBundle := ts.RegisterBundle("python_with_auth_check", pythonBundleWithAuthCheck(validToken, unused))

		ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
			spec.Proxy.ListenPath = "/test-api/"
			spec.UseKeylessAccess = false
			spec.EnableCoProcessAuth = true
			spec.CustomMiddlewareBundle = authCheckBundle
			spec.VersionData.NotVersioned = true
		}, func(spec *gateway.APISpec) {
			spec.Proxy.ListenPath = "/test-api-with-customplugin-auth-enabled/"
			spec.UseKeylessAccess = false
			spec.CustomPluginAuthEnabled = true
			spec.CustomMiddlewareBundle = authCheckBundle
			spec.VersionData.NotVersioned = true
		})

		validAuth := map[string]string{"Authorization": validToken}
		invalidAuth := map[string]string{"Authorization": "invalid_token"}

		ts.Run(t, []test.TestCase{
			{Path: "/test-api/", Code: http.StatusOK, Headers: validAuth},
			{Path: "/test-api/", Code: http.StatusForbidden, Headers: invalidAuth},
			{Path: "/test-api/", Code: http.StatusForbidden, Headers: validAuth},

			// Delete sessions so that next set of tests works afresh
			{Method: http.MethodDelete, Path: "/tyk/keys/" + validToken, AdminAuth: true, Code: http.StatusOK, BodyMatch: `"action":"deleted"`},

			{Path: "/test-api-with-customplugin-auth-enabled/", Code: http.StatusOK, Headers: validAuth},
			{Path: "/test-api-with-customplugin-auth-enabled/", Code: http.StatusForbidden, Headers: invalidAuth},
			{Path: "/test-api-with-customplugin-auth-enabled/", Code: http.StatusForbidden, Headers: validAuth},
		}...)
	})

	t.Run("Auth with policy", func(t *testing.T) {
		ts := setupGateway()
		defer ts.Close()

		validToken := uuid.NewHex()
		authCheckBundle := ts.RegisterBundle("python_with_auth_check", pythonBundleWithAuthCheck(unused, validToken))

		specs := ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
			spec.Auth.AuthHeaderName = "Authorization"
			spec.Proxy.ListenPath = "/test-api/"
			spec.UseKeylessAccess = false
			spec.EnableCoProcessAuth = true
			spec.CustomMiddlewareBundle = authCheckBundle
			spec.VersionData.NotVersioned = true
		})

		pID := ts.CreatePolicy(func(p *user.Policy) {
			p.QuotaMax = 1
			p.QuotaRenewalRate = 60
			p.AccessRights = map[string]user.AccessDefinition{"test": {
				APIID:    specs[0].APIID,
				Versions: []string{"Default"},
			}}

			t.Log(p.ID)
		})

		policyAuth := map[string]string{"authorization": validToken, "policy": pID}

		ts.Run(t, []test.TestCase{
			{Path: "/test-api/", Code: http.StatusOK, Headers: policyAuth},
			{Path: "/test-api/", Code: http.StatusForbidden, Headers: policyAuth},
		}...)
	})

	t.Run("Single-file bundle with post hook", func(t *testing.T) {
		ts := setupGateway()
		defer ts.Close()

		postHookBundle := ts.RegisterBundle("python_with_post_hook", pythonBundleWithPostHook())

		keyID := gateway.CreateSession(ts.Gw, func(s *user.SessionState) {
			s.MetaData = map[string]interface{}{
				"testkey":   map[string]interface{}{"nestedkey": "nestedvalue"},
				"stringkey": "testvalue",
			}
		})

		ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
			spec.Proxy.ListenPath = "/test-api-2/"
			spec.UseKeylessAccess = false
			spec.EnableCoProcessAuth = false
			spec.CustomMiddlewareBundle = postHookBundle
			spec.VersionData.NotVersioned = true
		})

		auth := map[string]string{"Authorization": keyID}

		ts.Run(t, []test.TestCase{
			{Path: "/test-api-2/", Code: http.StatusOK, Headers: auth},
		}...)
	})

	t.Run("Single-file bundle with response hook", func(t *testing.T) {
		ts := setupGateway()
		defer ts.Close()

		responseHookBundle := ts.RegisterBundle("python_with_response_hook", pythonBundleWithResponseHook())

		keyID := gateway.CreateSession(ts.Gw, func(s *user.SessionState) {
			s.MetaData = map[string]interface{}{
				"testkey":   map[string]interface{}{"nestedkey": "nestedvalue"},
				"stringkey": "testvalue",
			}
		})

		ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
			spec.Proxy.ListenPath = "/test-api-3/"
			spec.UseKeylessAccess = false
			spec.EnableCoProcessAuth = false
			spec.CustomMiddlewareBundle = responseHookBundle
			spec.VersionData.NotVersioned = true
		})

		auth := map[string]string{"Authorization": keyID}

		ts.Run(t, []test.TestCase{
			{Path: "/test-api-3/", Code: http.StatusOK, Headers: auth, BodyMatch: "newbody"},
		}...)
	})

	t.Run("Single-file bundle with pre hook and UTF-8/non-UTF-8 request data", func(t *testing.T) {
		ts := setupGateway()
		defer ts.Close()

		preHookBundle := ts.RegisterBundle("python_with_pre_hook", pythonBundleWithPreHook())

		ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
			spec.Proxy.ListenPath = "/test-api-2/"
			spec.UseKeylessAccess = true
			spec.EnableCoProcessAuth = false
			spec.CustomMiddlewareBundle = preHookBundle
			spec.VersionData.NotVersioned = true
		})

		fileData := gateway.GenerateTestBinaryData()
		var buf bytes.Buffer
		multipartWriter := multipart.NewWriter(&buf)
		file, err := multipartWriter.CreateFormFile("file", "test.bin")
		if err != nil {
			t.Fatalf("Couldn't use multipart writer: %s", err.Error())
		}
		_, err = fileData.WriteTo(file)
		if err != nil {
			t.Fatalf("Couldn't write to multipart file: %s", err.Error())
		}
		field, err := multipartWriter.CreateFormField("testfield")
		if err != nil {
			t.Fatalf("Couldn't use multipart writer: %s", err.Error())
		}
		_, err = field.Write([]byte("testvalue"))
		if err != nil {
			t.Fatalf("Couldn't write to form field: %s", err.Error())
		}
		err = multipartWriter.Close()
		if err != nil {
			t.Fatalf("Couldn't close multipart writer: %s", err.Error())
		}

		ts.Run(t, []test.TestCase{
			{Path: "/test-api-2/", Code: http.StatusOK, Data: &buf, Headers: map[string]string{"Content-Type": multipartWriter.FormDataContentType()}},
			{Path: "/test-api-2/", Code: http.StatusOK, Data: "{}", Headers: map[string]string{"Content-Type": "application/json"}},
		}...)
	})

	t.Run("python post hook with url rewrite and method transform", func(t *testing.T) {
		ts := setupGateway()
		defer ts.Close()

		postRequestTransformHookBundle := ts.RegisterBundle("python_post_with_request_transform_hook", pythonPostRequestTransform())

		ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
			spec.Proxy.ListenPath = "/test-api-1/"
			spec.UseKeylessAccess = true
			spec.EnableCoProcessAuth = false
			spec.CustomMiddlewareBundle = postRequestTransformHookBundle

			v1 := spec.VersionData.Versions["v1"]
			v1.UseExtendedPaths = true
			v1.ExtendedPaths.URLRewrite = []apidef.URLRewriteMeta{{
				Path:         "/get",
				Method:       http.MethodGet,
				MatchPattern: "/get",
				RewriteTo:    "/test2",
			}}

			v1.ExtendedPaths.MethodTransforms = []apidef.MethodTransformMeta{{
				Path:     "/get",
				Method:   http.MethodGet,
				ToMethod: http.MethodPost,
			}}

			spec.VersionData.Versions["v1"] = v1

		}, func(spec *gateway.APISpec) {
			spec.Name = "test-api-2"
			spec.Proxy.ListenPath = "/test-api-2/"
			spec.UseKeylessAccess = true
			spec.EnableCoProcessAuth = false
			spec.UseKeylessAccess = true
		})

		ts.Run(t, []test.TestCase{
			{Path: "/test-api-1/get", Code: http.StatusOK, BodyMatch: "newpath"},
			{Path: "/test-api-1/get", Code: http.StatusOK, BodyMatch: "GET"},
			{Path: "/test-api-1/post", Code: http.StatusOK, BodyNotMatch: "newpath"},
		}...)
	})
}
