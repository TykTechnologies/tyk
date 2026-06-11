package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// TestPRMMirrorMode_SuffixRoute spins up a fake remote MCP that returns a
// PRM doc at the path-suffix variant URL (the way Atlassian/Notion do it),
// fronts it with a Tyk MCP API in mirror mode, and asserts that probes to
// `<gateway>/.well-known/oauth-protected-resource<listen-path>` return the
// upstream's doc with `resource` rewritten to the gateway URL — the exact
// shape mcp-remote needs for RFC 9728 §3.3 origin validation to pass.
func TestPRMMirrorMode_SuffixRoute(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/.well-known/oauth-protected-resource/v1/mcp/authv2" {
			w.Header().Set("Content-Type", "application/json")
			//nolint:errcheck // test fixture; HTTP response Write failure not actionable here
			_, _ = io.WriteString(w, `{
				"resource": "https://upstream.example/v1/mcp/authv2",
				"authorization_servers": ["https://auth.upstream.example/tenant"],
				"bearer_methods_supported": ["header"],
				"scopes_supported": ["read:foo", "write:foo"],
				"resource_documentation": "https://upstream.example/docs"
			}`)
			return
		}
		// Protocol traffic: 401 with bare bearer challenge.
		w.Header().Set("WWW-Authenticate", `Bearer realm="OAuth"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(upstream.Close)

	ts := StartTest(nil)
	defer ts.Close()

	const listenPath = "/jira/"

	oasDoc := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info:    &openapi3.Info{Title: "MCP Mirror", Version: "1.0"},
			Paths:   openapi3.NewPaths(),
		},
	}
	oasDoc.SetTykExtension(&oas.XTykAPIGateway{
		Info: oas.Info{Name: "mcp-mirror-test", State: oas.State{Active: true}},
		Upstream: oas.Upstream{
			URL: upstream.URL + "/v1/mcp/authv2",
		},
		Server: oas.Server{
			ListenPath: oas.ListenPath{Value: listenPath, Strip: true},
			Authentication: &oas.Authentication{
				ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{
					Enabled: true,
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.MarkAsMCP()
		spec.Proxy.ListenPath = listenPath
		spec.Proxy.TargetURL = upstream.URL + "/v1/mcp/authv2"
		spec.IsOAS = true
		spec.OAS = oasDoc
	})

	expectedResourcePrefix := "/jira/"

	t.Run("suffix route without trailing slash", func(t *testing.T) {
		ts.Gw.PRMCache().Invalidate(upstream.URL + "/.well-known/oauth-protected-resource/v1/mcp/authv2")

		resp, _ := ts.Run(t, test.TestCase{
			Method: http.MethodGet,
			Path:   "/.well-known/oauth-protected-resource/jira",
			Code:   http.StatusOK,
		})

		var doc map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&doc))
		got, _ := doc["resource"].(string)
		assert.True(t, strings.HasSuffix(got, expectedResourcePrefix), "resource %q should end in %q", got, expectedResourcePrefix)
		// Mirror mode redirects authorization_servers at Tyk's per-API
		// AS-proxy URL so we can rewrite the RFC 8707 resource parameter.
		authServers, _ := doc["authorization_servers"].([]any)
		require.Len(t, authServers, 1)
		asURL, _ := authServers[0].(string)
		assert.Contains(t, asURL, "/__tyk-as/test", "authorization_servers should point at the Tyk AS proxy: %s", asURL)
		// Pass-through fields are preserved.
		assert.Equal(t, "https://upstream.example/docs", doc["resource_documentation"])
	})

	t.Run("suffix route with trailing slash", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Method: http.MethodGet,
			Path:   "/.well-known/oauth-protected-resource/jira/",
			Code:   http.StatusOK,
			BodyMatchFunc: func(b []byte) bool {
				return strings.Contains(string(b), `"authorization_servers"`)
			},
		})
	})
}

// TestOAuth2PRM_MirrorMode is the regression guard for the PRM auto-migration
// (TT-17176). A mirror-shape MCP API (enabled, no resource/authorizationServers)
// migrated into the new-style oauth2.protectedResourceMetadata block must keep
// mirroring the upstream's PRM document. The new block wins over the deprecated
// top-level block, so the new serving path must itself mirror — otherwise the
// migrated API serves an empty static document instead of the upstream's.
func TestOAuth2PRM_MirrorMode(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/.well-known/oauth-protected-resource/v1/mcp/authv2" {
			w.Header().Set("Content-Type", "application/json")
			//nolint:errcheck // test fixture; HTTP response Write failure not actionable here
			_, _ = io.WriteString(w, `{
				"resource": "https://upstream.example/v1/mcp/authv2",
				"authorization_servers": ["https://auth.upstream.example/tenant"],
				"bearer_methods_supported": ["header"],
				"resource_documentation": "https://upstream.example/docs"
			}`)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="OAuth"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(upstream.Close)

	ts := StartTest(nil)
	defer ts.Close()

	const listenPath = "/jira-new/"

	oasDoc := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info:    &openapi3.Info{Title: "MCP Mirror New", Version: "1.0"},
			Paths:   openapi3.NewPaths(),
		},
	}
	oasDoc.SetTykExtension(&oas.XTykAPIGateway{
		Info:     oas.Info{Name: "mcp-mirror-new-test", State: oas.State{Active: true}},
		Upstream: oas.Upstream{URL: upstream.URL + "/v1/mcp/authv2"},
		Server: oas.Server{
			ListenPath: oas.ListenPath{Value: listenPath, Strip: true},
			Authentication: &oas.Authentication{
				Enabled: true,
				SecuritySchemes: oas.SecuritySchemes{
					"corpOAuth": &oas.OAuth2{
						Enabled: true,
						// Mirror shape: enabled, no Resource / AuthorizationServers.
						ProtectedResourceMetadata: &oas.OAuth2PRM{Enabled: true},
					},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.MarkAsMCP()
		spec.Proxy.ListenPath = listenPath
		spec.Proxy.TargetURL = upstream.URL + "/v1/mcp/authv2"
		spec.IsOAS = true
		spec.OAS = oasDoc
	})

	ts.Gw.PRMCache().Invalidate(upstream.URL + "/.well-known/oauth-protected-resource/v1/mcp/authv2")

	resp, _ := ts.Run(t, test.TestCase{
		Method: http.MethodGet,
		Path:   "/jira-new/.well-known/oauth-protected-resource",
		Code:   http.StatusOK,
	})

	var doc map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&doc))

	// Mirror mode rewrites `resource` to the gateway URL the client hit;
	// an empty static doc would leave it "".
	got, _ := doc["resource"].(string)
	assert.True(t, strings.HasSuffix(got, listenPath),
		"resource %q should be the rewritten gateway URL ending %q (mirror mode), not an empty static value", got, listenPath)

	// Mirror mode redirects authorization_servers at Tyk's per-API AS proxy.
	authServers, _ := doc["authorization_servers"].([]any)
	require.Len(t, authServers, 1,
		"expected mirrored authorization_servers; got %v (empty static doc?)", doc["authorization_servers"])
	asURL, _ := authServers[0].(string)
	assert.Contains(t, asURL, "/__tyk-as/", "authorization_servers should point at the Tyk AS proxy")

	// Pass-through fields from the upstream doc prove we mirrored, not assembled.
	assert.Equal(t, "https://upstream.example/docs", doc["resource_documentation"])
}

// TestPRMMirrorMode_OAuthProxy exercises the full mirror-mode OAuth flow:
// PRM points clients at Tyk's AS proxy, the AS metadata endpoint serves
// rewritten `authorization_endpoint`/`token_endpoint`, the authorize
// handler 302s to upstream with the `resource` parameter rewritten from
// gateway URL to upstream URL, and the token handler forwards POSTs with
// the same rewrite. This is the path that fixes RFC 8707-strict ASes
// (Notion).
func TestPRMMirrorMode_OAuthProxy(t *testing.T) {
	var (
		authorizeHits int
		tokenHits     int
		lastResource  string
	)

	// httptest.NewServer assigns its URL during construction, but the
	// handler we register needs that URL inside its responses (the
	// upstream PRM doc points at its own AS, which is the same host).
	// Construct first with a stub handler, then swap in the real one.
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(upstream.Close)
	upstream.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/.well-known/oauth-protected-resource/v1/mcp/authv2":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"resource":"https://upstream.example/v1/mcp/authv2","authorization_servers":["%s"]}`, upstream.URL) //nolint:errcheck
		case r.Method == http.MethodGet && r.URL.Path == "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"issuer":"%s","authorization_endpoint":"%s/authorize","token_endpoint":"%s/token","registration_endpoint":"%s/register"}`, //nolint:errcheck
				upstream.URL, upstream.URL, upstream.URL, upstream.URL)
		case r.Method == http.MethodGet && r.URL.Path == "/authorize":
			authorizeHits++
			lastResource = r.URL.Query().Get("resource")
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/token":
			tokenHits++
			_ = r.ParseForm() //nolint:errcheck
			lastResource = r.PostFormValue("resource")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"abc","token_type":"Bearer"}`)) //nolint:errcheck
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	ts := StartTest(nil)
	defer ts.Close()

	const listenPath = "/jira/"
	upstreamTarget := upstream.URL + "/v1/mcp/authv2"

	oasDoc := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info:    &openapi3.Info{Title: "OAuth Proxy", Version: "1.0"},
			Paths:   openapi3.NewPaths(),
		},
	}
	oasDoc.SetTykExtension(&oas.XTykAPIGateway{
		Info:     oas.Info{Name: "mcp-oauth-proxy-test", State: oas.State{Active: true}},
		Upstream: oas.Upstream{URL: upstreamTarget},
		Server: oas.Server{
			ListenPath: oas.ListenPath{Value: listenPath, Strip: true},
			Authentication: &oas.Authentication{
				ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{
					Enabled: true,
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.MarkAsMCP()
		spec.Proxy.ListenPath = listenPath
		spec.Proxy.TargetURL = upstreamTarget
		spec.IsOAS = true
		spec.OAS = oasDoc
	})
	ts.Gw.PRMCache().Invalidate(upstream.URL + "/.well-known/oauth-protected-resource/v1/mcp/authv2")

	t.Run("AS metadata endpoint rewrites authorize/token URLs", func(t *testing.T) {
		resp, _ := ts.Run(t, test.TestCase{
			Method: http.MethodGet,
			Path:   "/.well-known/oauth-authorization-server/__tyk-as/test",
			Code:   http.StatusOK,
		})
		var meta map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))
		authzEP, _ := meta["authorization_endpoint"].(string)
		tokenEP, _ := meta["token_endpoint"].(string)
		assert.Contains(t, authzEP, "/__tyk-as/test/authorize")
		assert.Contains(t, tokenEP, "/__tyk-as/test/token")
		// Issuer is preserved verbatim from upstream.
		assert.Equal(t, upstream.URL, meta["issuer"])
	})

	t.Run("authorize 302s with rewritten resource param", func(t *testing.T) {
		gatewayResource := "http%3A%2F%2Fgateway%2Fjira%2F"
		// Drive the request manually so we can inspect the redirect.
		client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		req, errReq := http.NewRequest(http.MethodGet,
			ts.URL+"/__tyk-as/test/authorize?response_type=code&client_id=cid&resource="+gatewayResource+"&state=s",
			nil)
		require.NoError(t, errReq)
		resp, err := client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusFound, resp.StatusCode)
		loc, err := resp.Location()
		require.NoError(t, err)
		assert.Equal(t, upstream.Listener.Addr().String(), loc.Host)
		assert.Equal(t, upstreamTarget, loc.Query().Get("resource"),
			"resource param must be rewritten to upstream URL")
	})

	t.Run("token forwards with rewritten resource", func(t *testing.T) {
		gatewayResource := "http://gateway/jira/"
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", "abc")
		form.Set("resource", gatewayResource)
		req, errReq := http.NewRequest(http.MethodPost, ts.URL+"/__tyk-as/test/token", strings.NewReader(form.Encode()))
		require.NoError(t, errReq)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		body, errBody := io.ReadAll(resp.Body)
		require.NoError(t, errBody)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", string(body))
		assert.Contains(t, string(body), `"access_token":"abc"`)
		assert.Equal(t, upstreamTarget, lastResource,
			"upstream token endpoint must see the upstream-URL resource value")
	})

	// authorize is only verified by the redirect URL (test client doesn't
	// follow redirects on purpose, so upstream's /authorize never fires).
	_ = authorizeHits
	assert.Equal(t, 1, tokenHits, "upstream /token should have been hit once")
}

// TestAugmentMCPWWWAuthenticate covers the response-side header rewrite
// that adds `resource_metadata=<gateway-prm-url>` when the upstream's 401
// challenge omits it.
func TestAugmentMCPWWWAuthenticate(t *testing.T) {
	mkSpec := func(mcp bool, prmEnabled bool) *APISpec {
		s := &APISpec{
			APIDefinition: &apidef.APIDefinition{IsOAS: true},
		}
		s.Proxy.ListenPath = "/jira/"
		if mcp {
			s.MarkAsMCP()
		}
		if prmEnabled {
			s.OAS.SetTykExtension(&oas.XTykAPIGateway{
				Server: oas.Server{
					ListenPath: oas.ListenPath{Value: "/jira/"},
					Authentication: &oas.Authentication{
						ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{
							Enabled: true,
						},
					},
				},
			})
		}
		return s
	}

	mkResponse := func(status int, wwwAuth string) *http.Response {
		req, err := http.NewRequest(http.MethodPost, "http://gw.example/jira/", nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		h := http.Header{}
		if wwwAuth != "" {
			h.Set(header.WWWAuthenticate, wwwAuth)
		}
		return &http.Response{StatusCode: status, Header: h, Request: req}
	}

	t.Run("appends resource_metadata when missing", func(t *testing.T) {
		res := mkResponse(http.StatusUnauthorized, `Bearer realm="OAuth"`)
		augmentMCPWWWAuthenticate(res, res.Request, mkSpec(true, true))
		got := res.Header.Get(header.WWWAuthenticate)
		assert.Contains(t, got, `Bearer realm="OAuth"`)
		assert.Contains(t, got, `resource_metadata="http://gw.example/.well-known/oauth-protected-resource/jira"`)
	})

	t.Run("overwrites upstream resource_metadata to gateway URL", func(t *testing.T) {
		// MCP clients (RFC 9728 §3.3) validate the PRM doc's `resource`
		// field against the URL they connected to (the gateway). If the
		// upstream advertises its own URL via resource_metadata, the
		// origin check fails. Mirror mode redirects the client at our
		// own PRM endpoint instead.
		original := `Bearer realm="OAuth", resource_metadata="https://upstream.example/.well-known/oauth-protected-resource/x"`
		res := mkResponse(http.StatusUnauthorized, original)
		augmentMCPWWWAuthenticate(res, res.Request, mkSpec(true, true))
		got := res.Header.Get(header.WWWAuthenticate)
		assert.Contains(t, got, `Bearer realm="OAuth"`)
		assert.Contains(t, got, `resource_metadata="http://gw.example/.well-known/oauth-protected-resource/jira"`)
		assert.NotContains(t, got, "upstream.example")
	})

	t.Run("noop on non-401", func(t *testing.T) {
		res := mkResponse(http.StatusOK, `Bearer realm="OAuth"`)
		augmentMCPWWWAuthenticate(res, res.Request, mkSpec(true, true))
		assert.Equal(t, `Bearer realm="OAuth"`, res.Header.Get(header.WWWAuthenticate))
	})

	t.Run("noop on non-MCP", func(t *testing.T) {
		res := mkResponse(http.StatusUnauthorized, `Bearer realm="OAuth"`)
		augmentMCPWWWAuthenticate(res, res.Request, mkSpec(false, true))
		assert.Equal(t, `Bearer realm="OAuth"`, res.Header.Get(header.WWWAuthenticate))
	})

	t.Run("MCP API with no explicit PRM still augments (default mirror)", func(t *testing.T) {
		// Mirror is the implicit default for MCP APIs without an
		// explicit PRM block, so augmentation should fire.
		res := mkResponse(http.StatusUnauthorized, `Bearer realm="OAuth"`)
		augmentMCPWWWAuthenticate(res, res.Request, mkSpec(true, false))
		got := res.Header.Get(header.WWWAuthenticate)
		assert.Contains(t, got, `resource_metadata="http://gw.example/.well-known/oauth-protected-resource/jira"`)
	})

	t.Run("noop when PRM explicitly disabled", func(t *testing.T) {
		s := &APISpec{APIDefinition: &apidef.APIDefinition{IsOAS: true}}
		s.Proxy.ListenPath = "/jira/"
		s.MarkAsMCP()
		s.OAS.SetTykExtension(&oas.XTykAPIGateway{
			Server: oas.Server{
				ListenPath: oas.ListenPath{Value: "/jira/"},
				Authentication: &oas.Authentication{
					ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{Enabled: false},
				},
			},
		})
		res := mkResponse(http.StatusUnauthorized, `Bearer realm="OAuth"`)
		augmentMCPWWWAuthenticate(res, res.Request, s)
		assert.Equal(t, `Bearer realm="OAuth"`, res.Header.Get(header.WWWAuthenticate))
	})
}
