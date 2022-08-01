package python

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/test"
)

var pythonIDExtractorHeaderValue = map[string]string{
	"manifest.json": `
		{
		    "file_list": [
		        "middleware.py"
		    ],
		    "custom_middleware": {
		        "driver": "python",
		        "auth_check": {
		            "name": "MyAuthHook"
		        },
		        "id_extractor": {
		        	"extract_from": "header",
		        	"extract_with": "value",
		        	"extractor_config": {
		        		"header_name": "Authorization"
		        	}
		        }
		    }
		}
	`,
	"middleware.py": `
import time
from tyk.decorators import *
from gateway import TykGateway as tyk

counter = 0

@Hook
def MyAuthHook(request, session, metadata, spec):
    global counter
    counter = counter + 1
    auth_header = request.get_header('Authorization')
    if auth_header == 'valid_token' and counter < 2:
        session.rate = 1000.0
        session.per = 1.0
        session.id_extractor_deadline = int(time.time()) + 60
        metadata["token"] = "valid_token"
    return request, session, metadata
	`,
}

var pythonIDExtractorFormValue = map[string]string{
	"manifest.json": `
		{
		    "file_list": [
		        "middleware.py"
		    ],
		    "custom_middleware": {
		        "driver": "python",
		        "auth_check": {
		            "name": "MyAuthHook"
		        },
		        "id_extractor": {
		        	"extract_from": "form",
		        	"extract_with": "value",
		        	"extractor_config": {
		        		"param_name": "auth"
		        	}
		        }
		    }
		}
	`,
	"middleware.py": `
import time
from tyk.decorators import *
from gateway import TykGateway as tyk
from urllib import parse

counter = 0

@Hook
def MyAuthHook(request, session, metadata, spec):
    global counter
    counter = counter + 1
    auth_param = parse.parse_qs(request.object.body)["auth"]
    if auth_param and auth_param[0] == 'valid_token' and counter < 2:
        session.rate = 1000.0
        session.per = 1.0
        session.id_extractor_deadline = int(time.time()) + 60
        metadata["token"] = "valid_token"
    return request, session, metadata
`,
}

var pythonIDExtractorHeaderRegex = map[string]string{
	"manifest.json": `
		{
		    "file_list": [
		        "middleware.py"
		    ],
		    "custom_middleware": {
		        "driver": "python",
		        "auth_check": {
		            "name": "MyAuthHook"
		        },
		        "id_extractor": {
		        	"extract_from": "header",
		        	"extract_with": "regex",
		        	"extractor_config": {
		        		"header_name": "Authorization",
						"regex_expression": "[0-9]+",
						"regex_match_index": 0
		        	}
		        }
		    }
		}
	`,
	"middleware.py": `
import time
from tyk.decorators import *
from gateway import TykGateway as tyk

counter = 0

@Hook
def MyAuthHook(request, session, metadata, spec):
    print("MyAuthHook3 is called")
    global counter
    counter = counter + 1
    _, auth_header = request.get_header('Authorization').split('-')
    if auth_header and auth_header == '12345' and counter < 2:
        session.rate = 1000.0
        session.per = 1.0
        session.id_extractor_deadline = int(time.time()) + 60
        metadata["token"] = "valid_token"
    return request, session, metadata
	`,
}

/* Value Extractor tests, using "header" source */
// Goal of ID extractor is to cache auth plugin calls
// Our `pythonBundleWithAuthCheck` plugin restrict more then 1 call
// With ID extractor, it should run multiple times (because cache)
func TestValueExtractorHeaderSource(t *testing.T) {
	test.Flaky(t)
	pythonVersion := test.GetPythonVersion()
	ts := gateway.StartTest(nil, gateway.TestConfig{
		CoprocessConfig: config.CoProcessConfig{
			EnableCoProcess:  true,
			PythonPathPrefix: pkgPath,
			PythonVersion:    pythonVersion,
		},
		Delay: 10 * time.Millisecond,
	})
	defer ts.Close()

	spec := gateway.BuildAPI(func(spec *gateway.APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = false
		spec.EnableCoProcessAuth = true
	})[0]
	t.Run("Header value", func(t *testing.T) {
		bundleID := ts.RegisterBundle("id_extractor_header_value", pythonIDExtractorHeaderValue)
		spec.CustomMiddlewareBundle = bundleID
		spec.APIID = "api1"

		ts.Gw.LoadAPI(spec)
		time.Sleep(1 * time.Second)

		ts.Run(t, []test.TestCase{
			{Path: "/", Headers: map[string]string{"Authorization": "valid_token"}, Code: http.StatusOK},
			{Path: "/", Headers: map[string]string{"Authorization": "valid_token"}, Code: http.StatusOK},
			{Path: "/", Headers: map[string]string{"Authorization": "invalid_token"}, Code: http.StatusForbidden},
		}...)
	})
	t.Run("Form value", func(t *testing.T) {
		bundleID := ts.RegisterBundle("id_extractor_form_value", pythonIDExtractorFormValue)
		spec.CustomMiddlewareBundle = bundleID
		spec.APIID = "api2"

		ts.Gw.LoadAPI(spec)
		time.Sleep(1 * time.Second)

		formHeaders := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}

		ts.Run(t, []test.TestCase{
			{Method: "POST", Path: "/", Headers: formHeaders, Data: url.Values{"auth": []string{"valid_token"}}.Encode(), Code: http.StatusOK},
			{Method: "POST", Path: "/", Headers: formHeaders, Data: url.Values{"auth": []string{"valid_token"}}.Encode(), Code: http.StatusOK},
			{Method: "POST", Path: "/", Headers: formHeaders, Data: url.Values{"auth": []string{"invalid_token"}}.Encode(), Code: http.StatusForbidden},
		}...)
	})
	t.Run("Header regex", func(t *testing.T) {
		bundleID := ts.RegisterBundle("id_extractor_header_regex", pythonIDExtractorHeaderRegex)
		spec.CustomMiddlewareBundle = bundleID
		spec.APIID = "api3"

		ts.Gw.LoadAPI(spec)
		time.Sleep(1 * time.Second)

		ts.Run(t, []test.TestCase{
			{Path: "/", Headers: map[string]string{"Authorization": "prefix-12345"}, Code: http.StatusOK},
			{Path: "/", Headers: map[string]string{"Authorization": "prefix-12345"}, Code: http.StatusOK},
			{Path: "/", Headers: map[string]string{"Authorization": "prefix-123456"}, Code: http.StatusForbidden},
		}...)
	})
}
