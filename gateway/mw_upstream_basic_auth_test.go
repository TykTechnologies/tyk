//go:build ee || dev

package gateway

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
)

func TestUpstreamBasicAuthentication(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(func() {
		ts.Close()
	})

	userName, password, customAuthHeader := "user", "password", "Custom-Auth"
	expectedAuth := fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(userName+":"+password)))

	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.Proxy.ListenPath = "/upstream-basic-auth-enabled/"
			spec.UseKeylessAccess = true
			spec.UpstreamAuth = apidef.UpstreamAuth{
				Enabled: true,
				BasicAuth: apidef.UpstreamBasicAuth{
					Enabled:  true,
					Username: userName,
					Password: password,
				},
			}
			spec.Proxy.StripListenPath = true
		}, func(spec *APISpec) {
			spec.Proxy.ListenPath = "/upstream-basic-auth-custom-header/"
			spec.UseKeylessAccess = true
			spec.UpstreamAuth = apidef.UpstreamAuth{
				Enabled: true,
				BasicAuth: apidef.UpstreamBasicAuth{
					Enabled:  true,
					Username: userName,
					Password: password,
					Header: apidef.AuthSource{
						Enabled: true,
						Name:    customAuthHeader,
					},
				},
			}
			spec.Proxy.StripListenPath = true
		},
		func(spec *APISpec) {
			spec.Proxy.ListenPath = "/upstream-basic-auth-disabled/"
			spec.UseKeylessAccess = true
			spec.UpstreamAuth = apidef.UpstreamAuth{
				Enabled: true,
				BasicAuth: apidef.UpstreamBasicAuth{
					Enabled:  false,
					Username: userName,
					Password: password,
				},
			}
			spec.Proxy.StripListenPath = true
		},
		func(spec *APISpec) {
			spec.Proxy.ListenPath = "/upstream-auth-disabled/"
			spec.UseKeylessAccess = true
			spec.UpstreamAuth = apidef.UpstreamAuth{
				Enabled: false,
			}
			spec.Proxy.StripListenPath = true
		},
	)

	ts.Run(t, test.TestCases{
		{
			Path: "/upstream-basic-auth-enabled/",
			Code: http.StatusOK,
			BodyMatchFunc: func(body []byte) bool {
				resp := struct {
					Headers map[string]string `json:"headers"`
				}{}
				err := json.Unmarshal(body, &resp)
				assert.NoError(t, err)

				assert.Contains(t, resp.Headers, header.Authorization)
				assert.NotEmpty(t, resp.Headers[header.Authorization])
				assert.Equal(t, expectedAuth, resp.Headers[header.Authorization])

				return true
			},
		},
		{
			Path: "/upstream-basic-auth-custom-header/",
			Code: http.StatusOK,
			BodyMatchFunc: func(body []byte) bool {
				resp := struct {
					Headers map[string]string `json:"headers"`
				}{}
				err := json.Unmarshal(body, &resp)
				assert.NoError(t, err)

				assert.Contains(t, resp.Headers, customAuthHeader)
				assert.NotEmpty(t, resp.Headers[customAuthHeader])
				assert.Equal(t, expectedAuth, resp.Headers[customAuthHeader])

				return true
			},
		},
		{
			Path: "/upstream-basic-auth-disabled/",
			Code: http.StatusOK,
			BodyMatchFunc: func(body []byte) bool {
				resp := struct {
					Headers map[string]string `json:"headers"`
				}{}
				err := json.Unmarshal(body, &resp)
				assert.NoError(t, err)

				assert.NotContains(t, resp.Headers, header.Authorization)

				return true
			},
		},
		{
			Path: "/upstream-auth-disabled/",
			Code: http.StatusOK,
			BodyMatchFunc: func(body []byte) bool {
				resp := struct {
					Headers map[string]string `json:"headers"`
				}{}
				err := json.Unmarshal(body, &resp)
				assert.NoError(t, err)

				assert.NotContains(t, resp.Headers, header.Authorization)

				return true
			},
		},
	}...)

}
