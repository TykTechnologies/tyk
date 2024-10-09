package gateway

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

func (ts *Test) TestPrepareBasicAuth(cacheDisabled bool) *user.SessionState {
	session := CreateStandardSession()
	session.BasicAuthData.Password = "password"
	session.AccessRights = map[string]user.AccessDefinition{"test": {APIID: "test", Versions: []string{"v1"}}}
	session.OrgID = "default"

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseBasicAuth = true
		spec.BasicAuth.DisableCaching = cacheDisabled
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"
		spec.OrgID = "default"
	})

	return session
}

func (ts *Test) TestPrepareContextVarsMiddleware() {
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
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
}

func (ts *Test) TestPrepareVirtualEndpoint(js, method, path string, proxyOnError, keyless, cacheEnabled, disabled bool) {
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test"
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = keyless
		spec.Auth = apidef.AuthConfig{AuthHeaderName: "Authorization"}
		virtualMeta := apidef.VirtualMeta{
			Disabled:             disabled,
			ResponseFunctionName: "testVirtData",
			FunctionSourceType:   apidef.UseBlob,
			FunctionSourceURI:    base64.StdEncoding.EncodeToString([]byte(js)),
			Path:                 path,
			Method:               method,
			ProxyOnError:         proxyOnError,
		}
		if !keyless {
			virtualMeta.UseSession = true
		}
		v := spec.VersionData.Versions["v1"]
		v.UseExtendedPaths = true
		v.ExtendedPaths = apidef.ExtendedPathsSet{
			Virtual: []apidef.VirtualMeta{virtualMeta},
		}
		spec.VersionData.Versions["v1"] = v

		spec.ConfigData = map[string]interface{}{
			"foo": "x",
			"bar": map[string]interface{}{"y": 3},
		}

		// Address https://github.com/TykTechnologies/tyk/issues/1356
		// VP should work with cache enabled
		spec.CacheOptions = apidef.CacheOptions{
			EnableCache:                cacheEnabled,
			EnableUpstreamCacheControl: true,
			CacheTimeout:               60,
			CacheAllSafeRequests:       true,
		}
	})
}

var testJsonSchema = `{
    "title": "Person",
    "type": "object",
    "properties": {
        "firstName": {
            "type": "string"
        },
        "lastName": {
            "type": "string"
        },
        "age": {
            "description": "Age in years",
            "type": "integer",
            "minimum": 0
        },
		"objs":{
			"enum":["a","b","c"],
			"type":"string"
		}
    },
    "required": ["firstName", "lastName"]
}`

func (ts *Test) TestPrepareValidateJSONSchema(enabled bool) {
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			json.Unmarshal([]byte(`[
				{
					"disabled": `+fmt.Sprintf("%v,", !enabled)+`
					"path": "/v",
					"method": "POST",
					"schema": `+testJsonSchema+`
				}
			]`), &v.ExtendedPaths.ValidateJSON)
		})

		spec.Proxy.ListenPath = "/"
	})
}
