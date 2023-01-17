//go:build goplugin
// +build goplugin

package gateway

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
	"github.com/stretchr/testify/assert"
)

// TestLoadPlugin test the function to load a middleware goplugin
// ToDo: find out how to successfully load a plugin for testing
func TestLoadPlugin(t *testing.T) {
	plugin := GoPluginMiddleware{
		Path: "/any-fake-path",
	}

	pluginLoaded := plugin.loadPlugin()
	assert.Equal(t, false, pluginLoaded)
}

// TestGoPluginMWs tests all possible Go-plugin MWs ("pre", "auth_check", "post_key_auth" and "post")
// Please see ./test/goplugins/test_goplugin.go for plugin implementation details

// run go build -buildmode=plugin -o goplugins.so in ./test/goplugins directory prior to running tests
func TestGoPluginMWs(t *testing.T) {

	ts := gateway.StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
		spec.APIID = "plugin_api"
		spec.Proxy.ListenPath = "/goplugin"
		spec.UseKeylessAccess = false
		spec.UseStandardAuth = false
		spec.UseGoPluginAuth = true
		spec.CustomMiddleware = apidef.MiddlewareSection{
			Driver: apidef.GoPluginDriver,
			Pre: []apidef.MiddlewareDefinition{
				{
					Name: "MyPluginPre",
					Path: "../test/goplugins/goplugins.so",
				},
			},
			AuthCheck: apidef.MiddlewareDefinition{
				Name: "MyPluginAuthCheck",
				Path: "../test/goplugins/goplugins.so",
			},
			PostKeyAuth: []apidef.MiddlewareDefinition{
				{
					Name: "MyPluginPostKeyAuth",
					Path: "../test/goplugins/goplugins.so",
				},
			},
			Post: []apidef.MiddlewareDefinition{
				{
					Name: "MyPluginPost",
					Path: "../test/goplugins/goplugins.so",
				},
			},
		}
		configData := map[string]interface{}{
			"my-context-data": "my-plugin-config",
		}
		spec.ConfigData = configData
	}, func(spec *gateway.APISpec) {
		spec.APIID = "plugin_api_with_use_custom_plugin_auth"
		spec.Proxy.ListenPath = "/goplugin-custom-plugin-auth"
		spec.UseKeylessAccess = false
		spec.UseStandardAuth = false
		spec.CustomPluginAuthEnabled = true
		spec.CustomMiddleware = apidef.MiddlewareSection{
			Driver: apidef.GoPluginDriver,
			Pre: []apidef.MiddlewareDefinition{
				{
					Name: "MyPluginPre",
					Path: "../test/goplugins/goplugins.so",
				},
			},
			AuthCheck: apidef.MiddlewareDefinition{
				Name: "MyPluginAuthCheck",
				Path: "../test/goplugins/goplugins.so",
			},
			PostKeyAuth: []apidef.MiddlewareDefinition{
				{
					Name: "MyPluginPostKeyAuth",
					Path: "../test/goplugins/goplugins.so",
				},
			},
			Post: []apidef.MiddlewareDefinition{
				{
					Name: "MyPluginPost",
					Path: "../test/goplugins/goplugins.so",
				},
			},
		}
		configData := map[string]interface{}{
			"my-context-data": "my-plugin-config",
		}
		spec.ConfigData = configData
	})

	t.Run("Run Go-plugin auth failed", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{
				Path:    "/goplugin/plugin_hit",
				Headers: map[string]string{"Authorization": "invalid_token"},
				HeadersMatch: map[string]string{
					"X-Auth-Result": "failed",
				},
				Code:      http.StatusForbidden,
				BodyMatch: "auth failed",
			},
			{
				Path:    "/goplugin-custom-plugin-auth/plugin_hit",
				Headers: map[string]string{"Authorization": "invalid_token"},
				HeadersMatch: map[string]string{
					"X-Auth-Result": "failed",
				},
				Code:      http.StatusForbidden,
				BodyMatch: "auth failed",
			},
		}...)
	})

	t.Run("Run Go-plugin all middle-wares", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{
				Path:    "/goplugin/plugin_hit",
				Headers: map[string]string{"Authorization": "abc"},
				Code:    http.StatusOK,
				HeadersMatch: map[string]string{
					"X-Initial-URI":   "/goplugin/plugin_hit",
					"X-Auth-Result":   "OK",
					"X-Session-Alias": "abc-session",
					"X-Plugin-Data":   "my-plugin-config",
				},
				BodyMatch: `"message":"post message"`,
			},
			{
				Method:    "DELETE",
				Path:      "/tyk/keys/abc",
				AdminAuth: true,
				Code:      http.StatusOK,
				BodyMatch: `"action":"deleted"`,
			},
			{
				Path:    "/goplugin-custom-plugin-auth/plugin_hit",
				Headers: map[string]string{"Authorization": "abc"},
				Code:    http.StatusOK,
				HeadersMatch: map[string]string{
					"X-Initial-URI":   "/goplugin-custom-plugin-auth/plugin_hit",
					"X-Auth-Result":   "OK",
					"X-Session-Alias": "abc-session",
					"X-Plugin-Data":   "my-plugin-config",
				},
				BodyMatch: `"message":"post message"`,
			},
			{
				Method:    "DELETE",
				Path:      "/tyk/keys/abc",
				AdminAuth: true,
				Code:      http.StatusOK,
				BodyMatch: `"action":"deleted"`,
			},
		}...)
	})
}

func TestGoPluginResponseHook(t *testing.T) {

	ts := gateway.StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
		spec.APIID = "plugin_api"
		spec.Proxy.ListenPath = "/goplugin"
		spec.UseKeylessAccess = true
		spec.UseStandardAuth = false
		spec.UseGoPluginAuth = false
		spec.CustomMiddleware = apidef.MiddlewareSection{
			Driver: apidef.GoPluginDriver,
			Response: []apidef.MiddlewareDefinition{
				{
					Name: "MyPluginResponse",
					Path: "../test/goplugins/goplugins.so",
				},
			},
		}
		configData := map[string]interface{}{
			"my-context-data": "my-plugin-config",
		}
		spec.ConfigData = configData
	})

	t.Run("Run Go-plugin all middle-wares", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{
				Path:    "/goplugin/plugin_hit",
				Headers: map[string]string{"Authorization": "abc"},
				Code:    http.StatusOK,
				HeadersMatch: map[string]string{
					"X-Response-Added": "resp-added",
					"X-Plugin-Data":    "my-plugin-config",
				},
				BodyMatch: `{"message":"response injected message"}`,
			},
		}...)
	})
}

func TestGoPluginPerPathSingleFile(t *testing.T) {

	ts := gateway.StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
		spec.APIID = "plugin_api"
		spec.Proxy.ListenPath = "/goplugin"
		spec.UseKeylessAccess = true
		spec.UseStandardAuth = false

		goPluginMetaFoo := apidef.GoPluginMeta{
			Path:       "/foo",
			Method:     "GET",
			PluginPath: "../test/goplugins/goplugins.so",
			SymbolName: "MyPluginPerPathFoo",
		}

		goPluginMetaBar := apidef.GoPluginMeta{
			Path:       "/bar",
			Method:     "GET",
			PluginPath: "../test/goplugins/goplugins.so",
			SymbolName: "MyPluginPerPathBar",
		}

		goPluginMetaResp := apidef.GoPluginMeta{
			Path:       "/resp",
			Method:     "GET",
			PluginPath: "../test/goplugins/goplugins.so",
			SymbolName: "MyPluginPerPathResp",
		}

		v := spec.VersionData.Versions["v1"]

		v.UseExtendedPaths = true
		v.ExtendedPaths = apidef.ExtendedPathsSet{
			GoPlugin: []apidef.GoPluginMeta{
				goPluginMetaFoo,
				goPluginMetaBar,
				goPluginMetaResp,
			},
		}
		spec.VersionData.Versions["v1"] = v

	})

	t.Run("Run Go-plugins on each path", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{
				Path:   "/goplugin/foo",
				Method: http.MethodGet,
				HeadersMatch: map[string]string{
					"X-foo": "foo",
				},
			},
			{
				Path:   "/goplugin/bar",
				Method: http.MethodGet,
				HeadersMatch: map[string]string{
					"X-bar": "bar",
				},
			},
			{
				Path:   "/goplugin/resp",
				Method: http.MethodGet,
				HeadersMatch: map[string]string{
					"Content-Type": "application/json",
				},
				Code:      http.StatusOK,
				BodyMatch: `{"current_time":"now"}`,
			},
		}...)
	})

}

func TestGoPluginAPIandPerPath(t *testing.T) {

	ts := gateway.StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
		spec.APIID = "plugin_api"
		spec.Proxy.ListenPath = "/goplugin"
		spec.UseKeylessAccess = true
		spec.UseStandardAuth = false
		spec.CustomMiddleware = apidef.MiddlewareSection{
			Driver: apidef.GoPluginDriver,
			Pre: []apidef.MiddlewareDefinition{
				{
					Name: "MyPluginPre",
					Path: "../test/goplugins/goplugins.so",
				},
			},
		}
		goPluginMetaFoo := apidef.GoPluginMeta{
			Path:       "/foo",
			Method:     "GET",
			PluginPath: "../test/goplugins/goplugins.so",
			SymbolName: "MyPluginPerPathFoo",
		}
		v := spec.VersionData.Versions["v1"]

		v.UseExtendedPaths = true
		v.ExtendedPaths = apidef.ExtendedPathsSet{
			GoPlugin: []apidef.GoPluginMeta{
				goPluginMetaFoo,
			},
		}
		spec.VersionData.Versions["v1"] = v

	})

	t.Run("Run on per API and per path on same def", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{
				Path: "/goplugin/foo",
				Code: http.StatusOK,
				HeadersMatch: map[string]string{
					"X-Initial-URI": "/goplugin/foo",
					"X-foo":         "foo",
				},
			},
		}...)
	})
}
