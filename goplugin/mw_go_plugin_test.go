//go:build goplugin
// +build goplugin

package goplugin_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/user"

	"github.com/TykTechnologies/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/test"
)

func goPluginFilename() string {
	if test.IsRaceEnabled() {
		return "../test/goplugins/goplugins_race.so"
	}
	return "../test/goplugins/goplugins.so"
}

/*func TestMain(m *testing.M) {
	os.Exit(gateway.InitTestMain(context.Background(), m))
}*/

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
					Path: goPluginFilename(),
				},
			},
			AuthCheck: apidef.MiddlewareDefinition{
				Name: "MyPluginAuthCheck",
				Path: goPluginFilename(),
			},
			PostKeyAuth: []apidef.MiddlewareDefinition{
				{
					Name: "MyPluginPostKeyAuth",
					Path: goPluginFilename(),
				},
			},
			Post: []apidef.MiddlewareDefinition{
				{
					Name: "MyPluginPost",
					Path: goPluginFilename(),
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
					Path: goPluginFilename(),
				},
			},
			AuthCheck: apidef.MiddlewareDefinition{
				Name: "MyPluginAuthCheck",
				Path: goPluginFilename(),
			},
			PostKeyAuth: []apidef.MiddlewareDefinition{
				{
					Name: "MyPluginPostKeyAuth",
					Path: goPluginFilename(),
				},
			},
			Post: []apidef.MiddlewareDefinition{
				{
					Name: "MyPluginPost",
					Path: goPluginFilename(),
				},
			},
		}
		configData := map[string]interface{}{
			"my-context-data": "my-plugin-config",
		}
		spec.ConfigData = configData
	}, func(spec *gateway.APISpec) {
		spec.APIID = "disabled_plugins"
		spec.Proxy.ListenPath = "/disabled-goplugins"
		spec.UseKeylessAccess = true
		spec.UseStandardAuth = false
		spec.CustomMiddleware = apidef.MiddlewareSection{
			Driver: apidef.GoPluginDriver,
			Pre: []apidef.MiddlewareDefinition{
				{
					Disabled: true,
					Name:     "MyPluginPre",
					Path:     goPluginFilename(),
				},
			},
			PostKeyAuth: []apidef.MiddlewareDefinition{
				{
					Disabled: true,
					Name:     "MyPluginPostKeyAuth",
					Path:     goPluginFilename(),
				},
			},
			Post: []apidef.MiddlewareDefinition{
				{
					Disabled: true,
					Name:     "MyPluginPost",
					Path:     goPluginFilename(),
				},
			},
		}
		configData := map[string]interface{}{
			"my-context-data": "my-plugin-config",
		}
		spec.ConfigData = configData
	},
		func(spec *gateway.APISpec) {
			spec.APIID = "disabled_auth_plugin"
			spec.Proxy.ListenPath = "/disabled-auth-goplugins"
			spec.UseKeylessAccess = false
			spec.UseStandardAuth = false
			spec.CustomPluginAuthEnabled = true
			spec.CustomMiddleware = apidef.MiddlewareSection{
				Driver: apidef.GoPluginDriver,
				Pre: []apidef.MiddlewareDefinition{
					{
						Disabled: true,
						Name:     "MyPluginPre",
						Path:     goPluginFilename(),
					},
				},
				AuthCheck: apidef.MiddlewareDefinition{
					Disabled: true,
					Name:     "MyPluginAuthCheck",
					Path:     goPluginFilename(),
				},
				PostKeyAuth: []apidef.MiddlewareDefinition{
					{
						Disabled: true,
						Name:     "MyPluginPostKeyAuth",
						Path:     goPluginFilename(),
					},
				},
				Post: []apidef.MiddlewareDefinition{
					{
						Disabled: true,
						Name:     "MyPluginPost",
						Path:     goPluginFilename(),
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

	t.Run("do not run all middlewares", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{
				Path:    "/disabled-goplugins/plugin_hit",
				Headers: map[string]string{"Authorization": "abc"},
				Code:    http.StatusOK,
				HeadersNotMatch: map[string]string{
					"X-Initial-URI":   "/goplugin/plugin_hit",
					"X-Auth-Result":   "OK",
					"X-Session-Alias": "abc-session",
					"X-Plugin-Data":   "my-plugin-config",
				},
				BodyNotMatch: `"message":"post message"`,
				BodyMatch:    `"Authorization":"abc"`,
			},
		}...)
	})

	t.Run("auth check middleware disabled - should error", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{
				Path:      "/disabled-auth-goplugins/plugin_hit",
				Headers:   map[string]string{"Authorization": "abc"},
				Code:      http.StatusForbidden,
				BodyMatch: `Access to this API has been disallowed`,
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
					Path: goPluginFilename(),
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
			PluginPath: goPluginFilename(),
			SymbolName: "MyPluginPerPathFoo",
		}

		goPluginMetaBar := apidef.GoPluginMeta{
			Path:       "/bar",
			Method:     "GET",
			PluginPath: goPluginFilename(),
			SymbolName: "MyPluginPerPathBar",
		}

		goPluginMetaResp := apidef.GoPluginMeta{
			Path:       "/resp",
			Method:     "GET",
			PluginPath: goPluginFilename(),
			SymbolName: "MyPluginPerPathResp",
		}

		goPluginMetaDisabled := apidef.GoPluginMeta{
			Disabled:   true,
			Path:       "/disabled",
			Method:     "GET",
			PluginPath: goPluginFilename(),
			SymbolName: "MyPluginPerPathResp",
		}

		v := spec.VersionData.Versions["v1"]

		v.UseExtendedPaths = true
		v.ExtendedPaths = apidef.ExtendedPathsSet{
			GoPlugin: []apidef.GoPluginMeta{
				goPluginMetaFoo,
				goPluginMetaBar,
				goPluginMetaResp,
				goPluginMetaDisabled,
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
			{
				Path:   "/goplugin/disabled",
				Method: http.MethodGet,
				HeadersNotMatch: map[string]string{
					"Content-Type": "application/json",
				},
				Code:         http.StatusOK,
				BodyNotMatch: `{"current_time":"now"}`,
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
					Path: goPluginFilename(),
				},
			},
		}
		goPluginMetaFoo := apidef.GoPluginMeta{
			Path:       "/foo",
			Method:     "GET",
			PluginPath: goPluginFilename(),
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

func TestGoPluginMiddleware_ProcessRequest_ShouldFailWhenNotLoaded(t *testing.T) {
	ts := gateway.StartTest(nil)
	defer ts.Close()

	api := ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = false
		spec.CustomPluginAuthEnabled = true
		spec.CustomMiddleware.Driver = apidef.GoPluginDriver
		spec.CustomMiddleware.AuthCheck.Name = "my-auth"
		spec.CustomMiddleware.AuthCheck.Path = "auth.so"
	})[0]

	_, _ = ts.Run(t, test.TestCase{
		Path: "/get", Code: http.StatusInternalServerError, BodyMatch: http.StatusText(http.StatusInternalServerError),
	})

	t.Run("path level", func(t *testing.T) {
		api.CustomPluginAuthEnabled = false
		api.UseKeylessAccess = true

		v := api.VersionData.Versions["v1"]
		v.UseExtendedPaths = true
		v.ExtendedPaths = apidef.ExtendedPathsSet{
			GoPlugin: []apidef.GoPluginMeta{
				{
					Path:       "/my-plugin",
					Method:     http.MethodGet,
					PluginPath: "non-existing.so",
					SymbolName: "NonExistingPlugin",
				},
			},
		}
		api.VersionData.Versions["v1"] = v
		ts.Gw.LoadAPI(api)

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/get", Code: http.StatusOK},
			{Path: "/my-plugin", Code: http.StatusInternalServerError, BodyMatch: http.StatusText(http.StatusInternalServerError)},
		}...)
	})
}

func TestGoPlugin_AccessingOASAPIDef(t *testing.T) {
	ts := gateway.StartTest(nil)
	defer ts.Close()

	const oasDocTitle = "My OAS Documentation"

	oasDoc := oas.OAS{}
	oasDoc.OpenAPI = "3.0.3"
	oasDoc.Info = &openapi3.Info{
		Version: "1",
		Title:   oasDocTitle,
	}
	oasDoc.Paths = openapi3.Paths{}

	oasDoc.SetTykExtension(&oas.XTykAPIGateway{})

	err := oasDoc.Validate(context.Background())
	assert.NoError(t, err)

	ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
		spec.IsOAS = true
		spec.OAS = oasDoc
		spec.Proxy.ListenPath = "/oas-goplugin/"
		spec.UseKeylessAccess = true
		spec.UseStandardAuth = false
		spec.CustomMiddleware = apidef.MiddlewareSection{
			Driver: apidef.GoPluginDriver,
			Pre: []apidef.MiddlewareDefinition{
				{
					Name: "MyPluginAccessingOASAPI",
					Path: goPluginFilename(),
				},
			},
		}
	})

	ts.Run(t, []test.TestCase{
		{
			Path: "/oas-goplugin/get",
			Code: http.StatusOK,
			HeadersMatch: map[string]string{
				"X-OAS-Doc-Title": oasDocTitle,
			},
		},
	}...)
}

func TestGoPlugin_MyResponsePluginAccessingOASAPI(t *testing.T) {
	ts := gateway.StartTest(nil)
	defer ts.Close()

	oasDoc := oas.OAS{}
	oasDoc.OpenAPI = "3.0.3"
	oasDoc.Info = &openapi3.Info{
		Version: "1",
		Title:   "My OAS Documentation TestGoPlugin_MyResponsePluginAccessingOASAPI",
	}
	oasDoc.Paths = openapi3.Paths{}
	oasDoc.SetTykExtension(&oas.XTykAPIGateway{})
	err := oasDoc.Validate(context.Background())

	require.NoError(t, err)

	t.Run("Run Go-plugin on standalone response plugin", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
			spec.IsOAS = true
			spec.OAS = oasDoc
			spec.Proxy.ListenPath = "/goplugin/stanalone_response_plugin"
			spec.UseKeylessAccess = true
			spec.UseStandardAuth = false
			spec.UseGoPluginAuth = false
			spec.CustomMiddleware = apidef.MiddlewareSection{
				Driver: apidef.GoPluginDriver,
				Response: []apidef.MiddlewareDefinition{
					{
						Name: "MyResponsePluginAccessingOASAPI",
						Path: goPluginFilename(),
					},
				},
			}
		})

		ts.Run(t, []test.TestCase{
			{
				Path: "/goplugin/stanalone_response_plugin/plugin_hit",
				Code: http.StatusOK,
				HeadersMatch: map[string]string{
					"X-OAS-Doc-Title": oasDoc.Info.Title,
				},
			},
		}...)
	})

	t.Run("request-pre and response plugins chained work good", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
			spec.IsOAS = true
			spec.OAS = oasDoc
			spec.Proxy.ListenPath = "/goplugin/request_and_response_plugin"
			spec.UseKeylessAccess = true
			spec.UseStandardAuth = false
			spec.UseGoPluginAuth = false
			spec.CustomMiddleware = apidef.MiddlewareSection{
				Driver: apidef.GoPluginDriver,
				Pre: []apidef.MiddlewareDefinition{
					{
						Name: "MyPluginAccessingOASAPI",
						Path: goPluginFilename(),
					},
				},
				Response: []apidef.MiddlewareDefinition{
					{
						Name: "MyResponsePluginAccessingOASAPI",
						Path: goPluginFilename(),
					},
				},
			}
		})

		ts.Run(t, []test.TestCase{
			{
				Path: "/goplugin/request_and_response_plugin/plugin_hit",
				Code: http.StatusOK,
				HeadersMatch: map[string]string{
					"X-OAS-Doc-Title":                        oasDoc.Info.Title,
					"X-My-Plugin-Accessing-OAS-API":          oasDoc.Info.Title,
					"X-My-Response-Plugin-Accessing-OAS-API": oasDoc.Info.Title,
				},
			},
		}...)
	})

	t.Run("chained response plugin work fine", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
			spec.IsOAS = true
			spec.OAS = oasDoc
			spec.Proxy.ListenPath = "/goplugin/request_chaining"
			spec.UseKeylessAccess = true
			spec.UseStandardAuth = false
			spec.UseGoPluginAuth = false
			spec.CustomMiddleware = apidef.MiddlewareSection{
				Driver: apidef.GoPluginDriver,
				Response: []apidef.MiddlewareDefinition{
					{
						Name: "MyResponsePluginAccessingOASAPI",
						Path: goPluginFilename(),
					},
					{
						Name: "MyResponsePluginAccessingOASAPI2",
						Path: goPluginFilename(),
					},
				},
			}
		})

		ts.Run(t, []test.TestCase{
			{
				Path: "/goplugin/request_chaining/plugin_hit",
				Code: http.StatusOK,
				HeadersMatch: map[string]string{
					"X-OAS-Doc-Title":                          oasDoc.Info.Title,
					"X-My-Response-Plugin-Accessing-OAS-API-2": oasDoc.Info.Title,
					"X-My-Response-Plugin-Accessing-OAS-API":   oasDoc.Info.Title,
				},
			},
		}...)
	})
}

func TestGoPlugin_PreventDoubleError(t *testing.T) {
	ts := gateway.StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
		spec.Proxy.ListenPath = "/my-goplugin/"
		spec.UseKeylessAccess = true
		spec.UseStandardAuth = false
		spec.CustomMiddleware = apidef.MiddlewareSection{
			Driver: apidef.GoPluginDriver,
			Pre: []apidef.MiddlewareDefinition{
				{
					Name: "MyPluginReturningError",
					Path: goPluginFilename(),
				},
			},
		}
	})

	ts.Run(t, []test.TestCase{
		{
			Path: "/my-goplugin/get",
			Code: http.StatusTeapot,
			BodyMatchFunc: func(bytes []byte) bool {
				assert.Equal(t, http.StatusText(http.StatusTeapot), string(bytes))
				return true
			},
		},
	}...)
}

func TestGoPlugin_ApplyPolicy(t *testing.T) {
	ts := gateway.StartTest(nil)
	defer ts.Close()

	ts.CreatePolicy(func(p *user.Policy) {
		p.ID = "my-pol"
		p.Rate = 114
	})

	ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
		spec.Proxy.ListenPath = "/my-goplugin/"
		spec.UseKeylessAccess = true
		spec.UseStandardAuth = false
		spec.CustomMiddleware = apidef.MiddlewareSection{
			Driver: apidef.GoPluginDriver,
			Pre: []apidef.MiddlewareDefinition{
				{
					Name: "MyPluginApplyingPolicy",
					Path: goPluginFilename(),
				},
			},
		}
	})

	ts.Run(t, []test.TestCase{
		{
			Path: "/my-goplugin/get",
			Code: http.StatusOK,
		},
	}...)

	session, found := ts.Gw.GlobalSessionManager.SessionDetail("", "my-key", false)
	assert.True(t, found)
	assert.Equal(t, float64(114), session.Rate)
}
