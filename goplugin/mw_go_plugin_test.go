// +build goplugin

package goplugin_test

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/test"
)

func TestMain(m *testing.M) {
	os.Exit(gateway.InitTestMain(context.Background(), m))
}

// TestGoPluginMWs tests all possible Go-plugin MWs ("pre", "auth_check", "post_key_auth" and "post")
// Please see ./test/goplugins/test_goplugin.go for plugin implementation details

// run go build -buildmode=plugin -o goplugins.so in ./test/goplugins directory prior to running tests
func TestGoPluginMWs(t *testing.T) {
	ts := gateway.StartTest()
	defer ts.Close()

	gateway.BuildAndLoadAPI(func(spec *gateway.APISpec) {
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
	})

	time.Sleep(1 * time.Second)

	t.Run("Run Go-plugin auth failed", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{
				Path:    "/goplugin/plugin_hit",
				Headers: map[string]string{"Authorization": "invalid_token"},
				HeadersMatch: map[string]string{
					"X-Auth-Result": "failed",
				},
				Code: http.StatusForbidden,
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
				},
				BodyMatch: `"message":"post message"`,
			},
			{
				Method:    "DELETE",
				Path:      "/tyk/keys/abc",
				AdminAuth: true,
				Code:      http.StatusOK,
				BodyMatch: `"action":"deleted"`},
		}...)
	})
}

func TestGoPluginResponseHook(t *testing.T) {
	ts := gateway.StartTest()
	defer ts.Close()

	gateway.BuildAndLoadAPI(func(spec *gateway.APISpec) {
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
	})

	time.Sleep(1 * time.Second)

	t.Run("Run Go-plugin all middle-wares", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{
				Path:    "/goplugin/plugin_hit",
				Headers: map[string]string{"Authorization": "abc"},
				Code:    http.StatusOK,
				HeadersMatch: map[string]string{
					"X-Response-Added": "resp-added",
				},
				BodyMatch: `{"message":"response injected message"}`,
			},
		}...)
	})
}
