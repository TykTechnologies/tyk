// +build goplugin

package gateway

import (
	"net/http"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
)

// TestGoPluginMWs tests all possible Go-plugin MWs ("pre", "auth_check", "post_key_auth" and "post")
// Please see ./test/goplugins/test_goplugins.go for plugin implementation details
func TestGoPluginMWs(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
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
