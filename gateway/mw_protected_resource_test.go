package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
)

func TestGetPRMConfig(t *testing.T) {
	t.Run("non-OAS API returns nil", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				IsOAS: false,
			},
		}
		assert.Nil(t, spec.GetPRMConfig())
	})

	t.Run("OAS without authentication returns nil", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				IsOAS: true,
			},
		}
		spec.OAS.SetTykExtension(&oas.XTykAPIGateway{
			Server: oas.Server{
				ListenPath: oas.ListenPath{Value: "/"},
			},
		})
		assert.Nil(t, spec.GetPRMConfig())
	})

	t.Run("PRM disabled returns nil", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				IsOAS: true,
			},
		}
		spec.OAS.SetTykExtension(&oas.XTykAPIGateway{
			Server: oas.Server{
				ListenPath: oas.ListenPath{Value: "/"},
				Authentication: &oas.Authentication{
					ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{
						Enabled: false,
					},
				},
			},
		})
		assert.Nil(t, spec.GetPRMConfig())
	})

	t.Run("PRM enabled returns config", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				IsOAS: true,
			},
		}
		prm := &oas.ProtectedResourceMetadata{
			Enabled:              true,
			Resource:             "https://api.example.com",
			AuthorizationServers: []string{"https://auth.example.com"},
			ScopesSupported:      []string{"read", "write"},
		}
		spec.OAS.SetTykExtension(&oas.XTykAPIGateway{
			Server: oas.Server{
				ListenPath: oas.ListenPath{Value: "/"},
				Authentication: &oas.Authentication{
					ProtectedResourceMetadata: prm,
				},
			},
		})
		result := spec.GetPRMConfig()
		assert.NotNil(t, result)
		assert.Equal(t, "https://api.example.com", result.Resource)
		assert.Equal(t, []string{"https://auth.example.com"}, result.AuthorizationServers)
		assert.Equal(t, []string{"read", "write"}, result.ScopesSupported)
	})
}

func TestPRMWellKnownEndpoint(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("PRM enabled returns metadata JSON", func(t *testing.T) {
		oasDoc := oas.OAS{
			T: openapi3.T{
				OpenAPI: "3.0.3",
				Info:    &openapi3.Info{Title: "PRM Test", Version: "1.0"},
				Paths:   openapi3.NewPaths(),
			},
		}
		oasDoc.SetTykExtension(&oas.XTykAPIGateway{
			Info: oas.Info{
				Name: "prm-test",
				State: oas.State{
					Active: true,
				},
			},
			Upstream: oas.Upstream{
				URL: "http://httpbin.org",
			},
			Server: oas.Server{
				ListenPath: oas.ListenPath{
					Value: "/prm-test/",
					Strip: true,
				},
				Authentication: &oas.Authentication{
					ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{
						Enabled:              true,
						Resource:             "https://api.example.com/resource",
						AuthorizationServers: []string{"https://auth.example.com"},
						ScopesSupported:      []string{"read", "write"},
					},
				},
			},
		})

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/prm-test/"
			spec.IsOAS = true
			spec.OAS = oasDoc
		})

		ts.Run(t, test.TestCase{
			Method:    http.MethodGet,
			Path:      "/prm-test/.well-known/oauth-protected-resource",
			Code:      http.StatusOK,
			BodyMatch: `"resource":"https://api.example.com/resource"`,
			HeadersMatch: map[string]string{
				header.ContentType: "application/json",
			},
		})

		// Also verify the full JSON structure
		ts.Run(t, test.TestCase{
			Method:    http.MethodGet,
			Path:      "/prm-test/.well-known/oauth-protected-resource",
			Code:      http.StatusOK,
			BodyMatch: `"authorization_servers":\["https://auth.example.com"\]`,
		})

		ts.Run(t, test.TestCase{
			Method:    http.MethodGet,
			Path:      "/prm-test/.well-known/oauth-protected-resource",
			Code:      http.StatusOK,
			BodyMatch: `"scopes_supported":\["read","write"\]`,
		})
	})

	t.Run("custom well-known path", func(t *testing.T) {
		oasDoc := oas.OAS{
			T: openapi3.T{
				OpenAPI: "3.0.3",
				Info:    &openapi3.Info{Title: "PRM Custom Path", Version: "1.0"},
				Paths:   openapi3.NewPaths(),
			},
		}
		oasDoc.SetTykExtension(&oas.XTykAPIGateway{
			Info: oas.Info{
				Name: "prm-custom-path",
				State: oas.State{
					Active: true,
				},
			},
			Upstream: oas.Upstream{
				URL: "http://httpbin.org",
			},
			Server: oas.Server{
				ListenPath: oas.ListenPath{
					Value: "/prm-custom/",
					Strip: true,
				},
				Authentication: &oas.Authentication{
					ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{
						Enabled:              true,
						WellKnownPath:        "custom/prm-metadata",
						Resource:             "https://api.example.com",
						AuthorizationServers: []string{"https://auth.example.com"},
					},
				},
			},
		})

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/prm-custom/"
			spec.IsOAS = true
			spec.OAS = oasDoc
		})

		ts.Run(t, test.TestCase{
			Method:    http.MethodGet,
			Path:      "/prm-custom/custom/prm-metadata",
			Code:      http.StatusOK,
			BodyMatch: `"resource":"https://api.example.com"`,
		})
	})

	t.Run("PRM disabled returns 200 from upstream (falls through)", func(t *testing.T) {
		oasDoc := oas.OAS{
			T: openapi3.T{
				OpenAPI: "3.0.3",
				Info:    &openapi3.Info{Title: "PRM Disabled", Version: "1.0"},
				Paths:   openapi3.NewPaths(),
			},
		}
		oasDoc.SetTykExtension(&oas.XTykAPIGateway{
			Info: oas.Info{
				Name: "prm-disabled",
				State: oas.State{
					Active: true,
				},
			},
			Upstream: oas.Upstream{
				URL: "http://httpbin.org",
			},
			Server: oas.Server{
				ListenPath: oas.ListenPath{
					Value: "/prm-disabled/",
					Strip: true,
				},
				Authentication: &oas.Authentication{
					ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{
						Enabled: false,
					},
				},
			},
		})

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/prm-disabled/"
			spec.IsOAS = true
			spec.OAS = oasDoc
		})

		// The well-known path should NOT be registered, so the request falls through
		// to the normal middleware chain (proxy to upstream or 404 depending on upstream)
		ts.Run(t, test.TestCase{
			Method:       http.MethodGet,
			Path:         "/prm-disabled/.well-known/oauth-protected-resource",
			Code:         http.StatusOK,
			BodyNotMatch: `"resource"`,
		})
	})
}

func TestPRMWWWAuthenticateHeader(t *testing.T) {
	t.Run("header set when PRM enabled", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				IsOAS: true,
				Proxy: apidef.ProxyConfig{
					ListenPath: "/test-api/",
				},
			},
		}
		spec.OAS.SetTykExtension(&oas.XTykAPIGateway{
			Server: oas.Server{
				ListenPath: oas.ListenPath{Value: "/test-api/"},
				Authentication: &oas.Authentication{
					ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{
						Enabled:              true,
						Resource:             "https://api.example.com",
						AuthorizationServers: []string{"https://auth.example.com"},
					},
				},
			},
		})

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/test-api/endpoint", nil)
		r.Host = "gateway.example.com"

		setPRMWWWAuthenticateHeader(w, r, spec)

		wwwAuth := w.Header().Get(header.WWWAuthenticate)
		assert.Contains(t, wwwAuth, `Bearer realm="tyk"`)
		assert.Contains(t, wwwAuth, `resource_metadata="http://gateway.example.com/test-api/.well-known/oauth-protected-resource"`)
	})

	t.Run("header not set when PRM disabled", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				IsOAS: true,
				Proxy: apidef.ProxyConfig{
					ListenPath: "/test-api/",
				},
			},
		}
		spec.OAS.SetTykExtension(&oas.XTykAPIGateway{
			Server: oas.Server{
				ListenPath: oas.ListenPath{Value: "/test-api/"},
			},
		})

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/test-api/endpoint", nil)

		setPRMWWWAuthenticateHeader(w, r, spec)

		assert.Empty(t, w.Header().Get(header.WWWAuthenticate))
	})

	t.Run("uses X-Forwarded-Proto for scheme", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				IsOAS: true,
				Proxy: apidef.ProxyConfig{
					ListenPath: "/test-api/",
				},
			},
		}
		spec.OAS.SetTykExtension(&oas.XTykAPIGateway{
			Server: oas.Server{
				ListenPath: oas.ListenPath{Value: "/test-api/"},
				Authentication: &oas.Authentication{
					ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{
						Enabled:              true,
						Resource:             "https://api.example.com",
						AuthorizationServers: []string{"https://auth.example.com"},
					},
				},
			},
		})

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/test-api/endpoint", nil)
		r.Host = "gateway.example.com"
		r.Header.Set(header.XForwardProto, "https")

		setPRMWWWAuthenticateHeader(w, r, spec)

		wwwAuth := w.Header().Get(header.WWWAuthenticate)
		assert.Contains(t, wwwAuth, `resource_metadata="https://gateway.example.com/test-api/.well-known/oauth-protected-resource"`)
	})

	t.Run("non-OAS API does not set header", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				IsOAS: false,
			},
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/endpoint", nil)

		setPRMWWWAuthenticateHeader(w, r, spec)

		assert.Empty(t, w.Header().Get(header.WWWAuthenticate))
	})
}

func TestJWTMiddleware_PRMWWWAuthenticate(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("JWT missing auth header returns WWW-Authenticate when PRM enabled", func(t *testing.T) {
		oasDoc := oas.OAS{
			T: openapi3.T{
				OpenAPI: "3.0.3",
				Info:    &openapi3.Info{Title: "JWT PRM Test", Version: "1.0"},
				Paths:   openapi3.NewPaths(),
			},
		}
		oasDoc.SetTykExtension(&oas.XTykAPIGateway{
			Info: oas.Info{
				Name: "jwt-prm-test",
				State: oas.State{
					Active: true,
				},
			},
			Upstream: oas.Upstream{
				URL: "http://httpbin.org",
			},
			Server: oas.Server{
				ListenPath: oas.ListenPath{
					Value: "/jwt-prm/",
					Strip: true,
				},
				Authentication: &oas.Authentication{
					ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{
						Enabled:              true,
						Resource:             "https://api.example.com",
						AuthorizationServers: []string{"https://auth.example.com"},
					},
				},
			},
		})

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.EnableJWT = true
			spec.JWTSigningMethod = HMACSign
			spec.Proxy.ListenPath = "/jwt-prm/"
			spec.IsOAS = true
			spec.OAS = oasDoc
		})

		resp, _ := ts.Run(t, test.TestCase{
			Method: http.MethodGet,
			Path:   "/jwt-prm/test",
			Code:   http.StatusBadRequest,
		})

		wwwAuth := resp.Header.Get(header.WWWAuthenticate)
		assert.Contains(t, wwwAuth, `Bearer realm="tyk"`)
		assert.Contains(t, wwwAuth, `resource_metadata=`)
		assert.Contains(t, wwwAuth, `.well-known/oauth-protected-resource`)
	})

	t.Run("JWT missing auth header no PRM means no WWW-Authenticate", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.EnableJWT = true
			spec.JWTSigningMethod = HMACSign
			spec.Proxy.ListenPath = "/jwt-no-prm/"
		})

		ts.Run(t, test.TestCase{
			Method: http.MethodGet,
			Path:   "/jwt-no-prm/test",
			Code:   http.StatusBadRequest,
			HeadersNotMatch: map[string]string{
				header.WWWAuthenticate: `Bearer realm="tyk"`,
			},
		})
	})
}

func TestAuthKeyMiddleware_PRMWWWAuthenticate(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("AuthKey missing header returns WWW-Authenticate when PRM enabled", func(t *testing.T) {
		oasDoc := oas.OAS{
			T: openapi3.T{
				OpenAPI: "3.0.3",
				Info:    &openapi3.Info{Title: "AuthKey PRM Test", Version: "1.0"},
				Paths:   openapi3.NewPaths(),
			},
		}
		oasDoc.SetTykExtension(&oas.XTykAPIGateway{
			Info: oas.Info{
				Name: "authkey-prm-test",
				State: oas.State{
					Active: true,
				},
			},
			Upstream: oas.Upstream{
				URL: "http://httpbin.org",
			},
			Server: oas.Server{
				ListenPath: oas.ListenPath{
					Value: "/authkey-prm/",
					Strip: true,
				},
				Authentication: &oas.Authentication{
					ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{
						Enabled:              true,
						Resource:             "https://api.example.com",
						AuthorizationServers: []string{"https://auth.example.com"},
					},
				},
			},
		})

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.UseStandardAuth = true
			spec.Proxy.ListenPath = "/authkey-prm/"
			spec.IsOAS = true
			spec.OAS = oasDoc
		})

		resp, _ := ts.Run(t, test.TestCase{
			Method: http.MethodGet,
			Path:   "/authkey-prm/test",
			Code:   http.StatusUnauthorized,
		})

		wwwAuth := resp.Header.Get(header.WWWAuthenticate)
		assert.Contains(t, wwwAuth, `Bearer realm="tyk"`)
		assert.Contains(t, wwwAuth, `resource_metadata=`)
		assert.Contains(t, wwwAuth, `.well-known/oauth-protected-resource`)
	})
}
