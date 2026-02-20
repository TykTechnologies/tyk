package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

	t.Run("PRM disabled does not serve metadata endpoint", func(t *testing.T) {
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

		// The well-known path should NOT be registered as a PRM endpoint,
		// so the request falls through to the normal middleware chain.
		// We check that the response body does NOT contain the PRM JSON fields.
		resp, _ := ts.Run(t, test.TestCase{
			Method: http.MethodGet,
			Path:   "/prm-disabled/.well-known/oauth-protected-resource",
		})

		assert.NotEqual(t, "application/json", resp.Header.Get(header.ContentType),
			"PRM disabled API should not return application/json from the well-known path")
	})
}

func TestPRMMiddleware_ContextVariables(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("context variables resolved in resource", func(t *testing.T) {
		oasDoc := oas.OAS{
			T: openapi3.T{
				OpenAPI: "3.0.3",
				Info:    &openapi3.Info{Title: "PRM Context Vars", Version: "1.0"},
				Paths:   openapi3.NewPaths(),
			},
		}
		oasDoc.SetTykExtension(&oas.XTykAPIGateway{
			Info: oas.Info{
				Name: "prm-ctx-vars",
				State: oas.State{
					Active: true,
				},
			},
			Upstream: oas.Upstream{
				URL: "http://httpbin.org",
			},
			Server: oas.Server{
				ListenPath: oas.ListenPath{
					Value: "/prm-ctx/",
					Strip: true,
				},
				Authentication: &oas.Authentication{
					ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{
						Enabled:              true,
						Resource:             "https://example.com/$tyk_context.headers_X_Custom_Header",
						AuthorizationServers: []string{"https://auth.example.com"},
					},
				},
			},
		})

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = true
			spec.EnableContextVars = true
			spec.Proxy.ListenPath = "/prm-ctx/"
			spec.IsOAS = true
			spec.OAS = oasDoc
		})

		resp, _ := ts.Run(t, test.TestCase{
			Method: http.MethodGet,
			Path:   "/prm-ctx/.well-known/oauth-protected-resource",
			Headers: map[string]string{
				"X-Custom-Header": "test-value",
			},
			Code:      http.StatusOK,
			BodyMatch: `"resource":"https://example.com/test-value"`,
		})

		var doc prmResponseDocument
		err := json.NewDecoder(resp.Body).Decode(&doc)
		require.NoError(t, err)
		assert.Equal(t, "https://example.com/test-value", doc.Resource)
	})

	t.Run("non-well-known path passes through", func(t *testing.T) {
		oasDoc := oas.OAS{
			T: openapi3.T{
				OpenAPI: "3.0.3",
				Info:    &openapi3.Info{Title: "PRM Passthrough", Version: "1.0"},
				Paths:   openapi3.NewPaths(),
			},
		}
		oasDoc.SetTykExtension(&oas.XTykAPIGateway{
			Info: oas.Info{
				Name: "prm-passthrough",
				State: oas.State{
					Active: true,
				},
			},
			Upstream: oas.Upstream{
				URL: "http://httpbin.org",
			},
			Server: oas.Server{
				ListenPath: oas.ListenPath{
					Value: "/prm-pass/",
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
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/prm-pass/"
			spec.IsOAS = true
			spec.OAS = oasDoc
		})

		// A request to a non-well-known path should pass through (not return PRM doc)
		resp, _ := ts.Run(t, test.TestCase{
			Method: http.MethodGet,
			Path:   "/prm-pass/some-other-path",
			Code:   http.StatusOK,
		})

		// The response should NOT be the PRM document
		body, _ := io.ReadAll(resp.Body)
		assert.NotContains(t, string(body), `"authorization_servers"`)
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

		resp, _ := ts.Run(t, test.TestCase{
			Method: http.MethodGet,
			Path:   "/jwt-no-prm/test",
			Code:   http.StatusBadRequest,
		})

		assert.Empty(t, resp.Header.Get(header.WWWAuthenticate),
			"WWW-Authenticate header should not be present when PRM is not configured")
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

// TestPRMHappyPath_FullDiscoveryFlow tests the full MCP authorization discovery flow:
// 1. Client hits a JWT-protected endpoint without credentials
// 2. Gets an error response with WWW-Authenticate header containing resource_metadata URL
// 3. Client extracts the resource_metadata URL from the header
// 4. Client GETs the resource_metadata URL (PRM well-known endpoint)
// 5. Gets back a PRM JSON document with authorization_servers for discovery
// This validates the PRM endpoint is accessible without auth and the URL in
// the WWW-Authenticate header points to the correct, working PRM endpoint.
func TestPRMHappyPath_FullDiscoveryFlow(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const (
		listenPath = "/mcp-api/"
		resource   = "https://api.example.com/mcp"
		authServer = "https://auth.example.com"
		scope1     = "mcp:read"
		scope2     = "mcp:write"
	)

	oasDoc := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info:    &openapi3.Info{Title: "MCP Discovery Flow", Version: "1.0"},
			Paths:   openapi3.NewPaths(),
		},
	}
	oasDoc.SetTykExtension(&oas.XTykAPIGateway{
		Info: oas.Info{
			Name: "mcp-discovery-test",
			State: oas.State{
				Active: true,
			},
		},
		Upstream: oas.Upstream{
			URL: "http://httpbin.org",
		},
		Server: oas.Server{
			ListenPath: oas.ListenPath{
				Value: listenPath,
				Strip: true,
			},
			Authentication: &oas.Authentication{
				ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{
					Enabled:              true,
					Resource:             resource,
					AuthorizationServers: []string{authServer},
					ScopesSupported:      []string{scope1, scope2},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = HMACSign
		spec.Proxy.ListenPath = listenPath
		spec.IsOAS = true
		spec.OAS = oasDoc
	})

	// Step 1: Client requests a protected endpoint without credentials.
	// Expect an error response with a WWW-Authenticate header.
	resp, _ := ts.Run(t, test.TestCase{
		Method: http.MethodGet,
		Path:   "/mcp-api/tools/list",
		Code:   http.StatusBadRequest,
	})

	wwwAuth := resp.Header.Get(header.WWWAuthenticate)
	require.NotEmpty(t, wwwAuth, "WWW-Authenticate header must be present on auth failure")
	assert.Contains(t, wwwAuth, `Bearer realm="tyk"`)

	// Step 2: Extract resource_metadata URL from WWW-Authenticate header.
	// Header format: Bearer realm="tyk", resource_metadata="<url>"
	const prefix = `resource_metadata="`
	idx := strings.Index(wwwAuth, prefix)
	require.NotEqual(t, -1, idx, "WWW-Authenticate header must contain resource_metadata URL")
	metadataURLStart := idx + len(prefix)
	endIdx := strings.Index(wwwAuth[metadataURLStart:], `"`)
	require.NotEqual(t, -1, endIdx, "resource_metadata URL must be properly quoted")
	metadataURL := wwwAuth[metadataURLStart : metadataURLStart+endIdx]

	assert.Contains(t, metadataURL, listenPath)
	assert.Contains(t, metadataURL, ".well-known/oauth-protected-resource")

	// Step 3: Client fetches the PRM well-known endpoint using the extracted URL path.
	// The URL is absolute (http://host:port/path), extract just the path.
	prmPath := metadataURL[strings.Index(metadataURL, listenPath):]

	resp, _ = ts.Run(t, test.TestCase{
		Method: http.MethodGet,
		Path:   prmPath,
		Code:   http.StatusOK,
		HeadersMatch: map[string]string{
			header.ContentType: "application/json",
		},
	})

	// Step 4: Parse the PRM response and validate all fields.
	var prmDoc prmResponseDocument
	err := json.NewDecoder(resp.Body).Decode(&prmDoc)
	require.NoError(t, err, "PRM endpoint should return valid JSON")

	assert.Equal(t, resource, prmDoc.Resource,
		"PRM resource must match the configured resource identifier")
	assert.Equal(t, []string{authServer}, prmDoc.AuthorizationServers,
		"PRM must contain the configured authorization servers")
	assert.Equal(t, []string{scope1, scope2}, prmDoc.ScopesSupported,
		"PRM must contain the configured scopes")
}
