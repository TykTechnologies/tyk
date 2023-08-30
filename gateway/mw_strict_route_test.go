package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/stretchr/testify/assert"
)

func TestStrictRoutesMW_ProcessRequest(t *testing.T) {

	tests := []struct {
		name       string
		conf       config.Config
		spec       *APISpec
		reqPath    string
		statusCode int
	}{
		{
			name: "strict routes not enabled(reqPath==listenPath)",
			conf: config.Config{
				HttpServerOptions: config.HttpServerOptionsConfig{
					EnableStrictRoutes: false,
				},
			},
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					Proxy: apidef.ProxyConfig{
						ListenPath: "/listen-path",
					},
				},
			},
			reqPath:    "/listen-path",
			statusCode: http.StatusOK,
		},
		{
			name: "strict routes not enabled(reqPath!=listenPath)",
			conf: config.Config{
				HttpServerOptions: config.HttpServerOptionsConfig{
					EnableStrictRoutes: false,
				},
			},
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					Proxy: apidef.ProxyConfig{
						ListenPath: "/listen-path",
					},
				},
			},
			reqPath:    "/listen-pathh",
			statusCode: http.StatusOK,
		},
		{
			name: "strict routes enabled(reqPath!=listenPath)",
			conf: config.Config{
				HttpServerOptions: config.HttpServerOptionsConfig{
					EnableStrictRoutes: true,
				},
			},
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					Proxy: apidef.ProxyConfig{
						ListenPath: "/listen-path",
					},
				},
			},
			reqPath:    "/listen-pathh",
			statusCode: mwStatusRespond,
		},
		{
			name: "strict routes enabled(listenPath with trailing slash)",
			conf: config.Config{
				HttpServerOptions: config.HttpServerOptionsConfig{
					EnableStrictRoutes: true,
				},
			},
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					Proxy: apidef.ProxyConfig{
						ListenPath: "/listen-path/",
					},
				},
			},
			reqPath:    "/listen-pathh",
			statusCode: mwStatusRespond,
		},
		{
			name: "strict routes enabled(listenPath with parameter)",
			conf: config.Config{
				HttpServerOptions: config.HttpServerOptionsConfig{
					EnableStrictRoutes: true,
				},
			},
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					Proxy: apidef.ProxyConfig{
						ListenPath: "/{listen-path}/",
					},
				},
			},
			reqPath:    "/listen-pathh",
			statusCode: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			rec := httptest.NewRecorder()
			req := TestReq(t, "GET", tt.reqPath, nil)

			gw := &Gateway{}
			gw.config.Store(tt.conf)
			mw := &StrictRoutesMW{
				BaseMiddleware{
					Spec: tt.spec,
					Gw:   gw,
				},
			}
			_, code := mw.ProcessRequest(rec, req, nil)

			assert.Equal(t, tt.statusCode, code)

			if tt.statusCode == mwStatusRespond {
				res := rec.Result()
				defer res.Body.Close()
				data, err := io.ReadAll(res.Body)
				assert.NoError(t, err)
				assert.Equal(t, http.StatusText(http.StatusNotFound), string(data))
			}

		})
	}
}

func TestStrictRoutesMW_EnabledForSpec(t *testing.T) {
	tests := []struct {
		name    string
		conf    config.Config
		enabled bool
	}{
		{
			name: "strict routes disabled",
			conf: config.Config{
				HttpServerOptions: config.HttpServerOptionsConfig{
					EnableStrictRoutes: false,
				},
			},
			enabled: false,
		},
		{
			name: "strict routes enabled",
			conf: config.Config{
				HttpServerOptions: config.HttpServerOptionsConfig{
					EnableStrictRoutes: true,
				},
			},
			enabled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := &Gateway{}
			gw.config.Store(tt.conf)
			mw := &StrictRoutesMW{
				BaseMiddleware{
					Gw: gw,
				},
			}
			assert.Equal(t, tt.enabled, mw.EnabledForSpec())
		})
	}
}
