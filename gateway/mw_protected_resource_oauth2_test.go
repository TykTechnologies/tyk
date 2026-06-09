package gateway

import (
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
)

// newOAuth2PRMOAS builds an OAS doc with the new-style
// oauth2.protectedResourceMetadata block. When
// scopeCheck is non-nil it is attached too, so the same fixture drives
// both the PRM-serving and the resource_metadata-on-challenge cases.
func newOAuth2PRMOAS(listenPath string, prm *oas.OAuth2PRM, sc *oas.OAuth2ScopeCheck) oas.OAS {
	doc := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info:    &openapi3.Info{Title: "oauth2-prm", Version: "1.0"},
			Paths:   openapi3.NewPaths(),
			Components: &openapi3.Components{
				SecuritySchemes: openapi3.SecuritySchemes{
					"corpOAuth": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type: "oauth2",
							Flows: &openapi3.OAuthFlows{
								AuthorizationCode: &openapi3.OAuthFlow{
									AuthorizationURL: "/oauth/authorize",
									TokenURL:         "/oauth/token",
									Scopes:           map[string]string{},
								},
							},
						},
					},
				},
			},
		},
	}
	doc.SetTykExtension(&oas.XTykAPIGateway{
		Info:     oas.Info{Name: "oauth2-prm", State: oas.State{Active: true}},
		Upstream: oas.Upstream{URL: TestHttpAny},
		Server: oas.Server{
			ListenPath: oas.ListenPath{Value: listenPath, Strip: true},
			Authentication: &oas.Authentication{
				Enabled: true,
				SecuritySchemes: oas.SecuritySchemes{
					"corpOAuth": &oas.OAuth2{
						Enabled:                   true,
						ScopeCheck:                sc,
						ProtectedResourceMetadata: prm,
					},
				},
			},
		},
	})
	return doc
}

func loadOAuth2PRMAPI(ts *Test, listenPath string, doc oas.OAS) {
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = listenPath
		spec.IsOAS = true
		spec.OAS = doc
	})
}

func addPerOpSecurity(doc *oas.OAS, path string, scopes ...string) {
	pi := &openapi3.PathItem{Get: &openapi3.Operation{
		Security:  &openapi3.SecurityRequirements{{"corpOAuth": scopes}},
		Responses: openapi3.NewResponses(),
	}}
	doc.Paths.Set(path, pi)
}

// addCatalogScopes adds entries to the operator-authored flows.scopes
// catalog of the corpOAuth security scheme.
func addCatalogScopes(doc *oas.OAS, scopes ...string) {
	m := doc.Components.SecuritySchemes["corpOAuth"].Value.Flows.AuthorizationCode.Scopes
	for _, sc := range scopes {
		m[sc] = ""
	}
}

func TestOAuth2PRM_WellKnownEndpoint(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("default path — scopes union + bearer_methods_supported", func(t *testing.T) {
		doc := newOAuth2PRMOAS("/prm-new/", &oas.OAuth2PRM{
			Enabled:              true,
			Resource:             "https://api.example.com/resource",
			AuthorizationServers: []string{"https://kc/realms/test"},
		}, &oas.OAuth2ScopeCheck{Enabled: true})
		addCatalogScopes(&doc, "audit:read")
		doc.Security = append(doc.Security, openapi3.SecurityRequirement{"corpOAuth": {"api:access"}})
		addPerOpSecurity(&doc, "/users", "users:read")
		loadOAuth2PRMAPI(ts, "/prm-new/", doc)

		ts.Run(t,
			test.TestCase{
				Method:    http.MethodGet,
				Path:      "/prm-new/.well-known/oauth-protected-resource",
				Code:      http.StatusOK,
				BodyMatch: `"resource":"https://api.example.com/resource"`,
				HeadersMatch: map[string]string{
					header.ContentType: "application/json",
				},
			},
			test.TestCase{
				Method:    http.MethodGet,
				Path:      "/prm-new/.well-known/oauth-protected-resource",
				Code:      http.StatusOK,
				BodyMatch: `"bearer_methods_supported":\["header"\]`,
			},
			// scopes_supported is the sorted union: audit:read (flows.scopes
			// catalog) + api:access (root security) + users:read (per-op).
			test.TestCase{
				Method:    http.MethodGet,
				Path:      "/prm-new/.well-known/oauth-protected-resource",
				Code:      http.StatusOK,
				BodyMatch: `"scopes_supported":\["api:access","audit:read","users:read"\]`,
			},
		)
	})

	t.Run("custom wellKnownPath honored", func(t *testing.T) {
		doc := newOAuth2PRMOAS("/prm-custom/", &oas.OAuth2PRM{
			Enabled:              true,
			WellKnownPath:        ".well-known/custom-prm",
			Resource:             "https://api.example.com/",
			AuthorizationServers: []string{"https://kc/realms/test"},
		}, nil)
		loadOAuth2PRMAPI(ts, "/prm-custom/", doc)

		ts.Run(t, test.TestCase{
			Method:    http.MethodGet,
			Path:      "/prm-custom/.well-known/custom-prm",
			Code:      http.StatusOK,
			BodyMatch: `"resource":"https://api.example.com/"`,
		})
	})

	t.Run("autoDeriveScopes:false — only the flows.scopes catalog advertised", func(t *testing.T) {
		off := false
		doc := newOAuth2PRMOAS("/prm-noderive/", &oas.OAuth2PRM{
			Enabled:              true,
			Resource:             "https://api.example.com/",
			AuthorizationServers: []string{"https://kc/realms/test"},
			AutoDeriveScopes:     &off,
		}, &oas.OAuth2ScopeCheck{Enabled: true})
		addCatalogScopes(&doc, "audit:read")
		doc.Security = append(doc.Security, openapi3.SecurityRequirement{"corpOAuth": {"api:access"}})
		addPerOpSecurity(&doc, "/users", "users:read")
		loadOAuth2PRMAPI(ts, "/prm-noderive/", doc)

		ts.Run(t, test.TestCase{
			Method:    http.MethodGet,
			Path:      "/prm-noderive/.well-known/oauth-protected-resource",
			Code:      http.StatusOK,
			BodyMatch: `"scopes_supported":\["audit:read"\]`,
		})
	})
}

// TestOAuth2PRM_NewWinsOverOld pins the precedence rule: when both the
// deprecated authentication.protectedResourceMetadata and the new
// oauth2.protectedResourceMetadata are configured, the new one is the
// sole authority.
func TestOAuth2PRM_NewWinsOverOld(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	doc := newOAuth2PRMOAS("/prm-both/", &oas.OAuth2PRM{
		Enabled:              true,
		Resource:             "https://new.example.com/",
		AuthorizationServers: []string{"https://new-as/"},
	}, nil)
	doc.GetTykExtension().Server.Authentication.ProtectedResourceMetadata = &oas.ProtectedResourceMetadata{
		Enabled:              true,
		Resource:             "https://old.example.com/",
		AuthorizationServers: []string{"https://old-as/"},
	}
	loadOAuth2PRMAPI(ts, "/prm-both/", doc)

	ts.Run(t, test.TestCase{
		Method:       http.MethodGet,
		Path:         "/prm-both/.well-known/oauth-protected-resource",
		Code:         http.StatusOK,
		BodyMatch:    `"authorization_servers":\["https://new-as/"\]`,
		BodyNotMatch: "old-as",
	})
}

// TestOAuth2PRM_ServesWhenOAuth2MasterDisabled pins the migration's
// safety hatch: PRM publishing is independent of OAuth2 authentication
// enforcement. The dashboard migration creates the new oauth2 scheme
// with oauth2.enabled=false (so it doesn't silently turn on auth that
// wasn't there before) but oauth2.protectedResourceMetadata.enabled=true
// so the new PRM document is served. If a refactor ever wires
// GetOAuth2PRMConfig to check oauth2.enabled, every migrated customer
// stops publishing PRM until they manually flip the master switch.
func TestOAuth2PRM_ServesWhenOAuth2MasterDisabled(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	doc := newOAuth2PRMOAS("/prm-master-off/", &oas.OAuth2PRM{
		Enabled:              true,
		Resource:             "https://api.example.com/",
		AuthorizationServers: []string{"https://as.example.com/"},
	}, nil)
	doc.GetTykExtension().Server.Authentication.SecuritySchemes["corpOAuth"].(*oas.OAuth2).Enabled = false
	loadOAuth2PRMAPI(ts, "/prm-master-off/", doc)

	ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/prm-master-off/.well-known/oauth-protected-resource",
		Code:      http.StatusOK,
		BodyMatch: `"authorization_servers":\["https://as.example.com/"\]`,
	})
}

// TestOAuth2PRM_FallsBackToLegacyWhenNewBlockAbsent pins the legacy
// fallback path that the migration relies on: after the dashboard
// non-destructively copies the legacy top-level
// authentication.protectedResourceMetadata block to the new per-scheme
// oauth2.protectedResourceMetadata location, an operator may later
// remove the new block (reverting to the old location). The gateway
// must continue to serve PRM from the legacy block in that state.
func TestOAuth2PRM_FallsBackToLegacyWhenNewBlockAbsent(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	doc := newOAuth2PRMOAS("/prm-fallback/", nil, nil)
	//nolint:staticcheck // intentional: pinning the legacy block's runtime fallback.
	doc.GetTykExtension().Server.Authentication.ProtectedResourceMetadata = &oas.ProtectedResourceMetadata{
		Enabled:              true,
		Resource:             "https://api.example.com/legacy",
		AuthorizationServers: []string{"https://old-as.example.com/"},
	}
	loadOAuth2PRMAPI(ts, "/prm-fallback/", doc)

	ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/prm-fallback/.well-known/oauth-protected-resource",
		Code:      http.StatusOK,
		BodyMatch: `"authorization_servers":\["https://old-as.example.com/"\]`,
	})
}

// TestOAuth2PRM_ResourceMetadataOnChallenge verifies the scope-check
// middleware appends an RFC 9728 §5.1 resource_metadata= parameter to
// its Bearer challenges when the API publishes a PRM document, and omits
// it when PRM is disabled. The PRM URL embeds the test server's random
// port, so these assertions are made against the live response header
// rather than an exact-match TestCase.
func TestOAuth2PRM_ResourceMetadataOnChallenge(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("403 insufficient_scope + 401 invalid_token carry resource_metadata", func(t *testing.T) {
		doc := newOAuth2PRMOAS("/prm-403/", &oas.OAuth2PRM{
			Enabled:              true,
			Resource:             "https://api.example.com/",
			AuthorizationServers: []string{"https://kc/realms/test"},
		}, &oas.OAuth2ScopeCheck{
			Enabled:     true,
			ScopeSource: oas.OAuth2ScopeSourceGlobal,
		})
		doc.Security = append(doc.Security, openapi3.SecurityRequirement{"corpOAuth": {"users:read"}})
		loadOAuth2PRMAPI(ts, "/prm-403/", doc)

		token := makeUnverifiedJWT(t, jwt.MapClaims{"scope": "openid"})
		resp, err := ts.Run(t, test.TestCase{
			Method:  http.MethodGet,
			Path:    "/prm-403/anything",
			Headers: map[string]string{"Authorization": "Bearer " + token},
			Code:    http.StatusForbidden,
		})
		assert.NoError(t, err)
		got := resp.Header.Get(header.WWWAuthenticate)
		assert.Contains(t, got, `error="insufficient_scope"`)
		assert.Contains(t, got, `scope="users:read"`)
		assert.Regexp(t, `resource_metadata="http://[^"]+/prm-403/\.well-known/oauth-protected-resource"`, got)

		resp, err = ts.Run(t, test.TestCase{
			Method: http.MethodGet,
			Path:   "/prm-403/anything",
			Code:   http.StatusUnauthorized,
		})
		assert.NoError(t, err)
		got = resp.Header.Get(header.WWWAuthenticate)
		assert.Contains(t, got, `error="invalid_token"`)
		assert.Regexp(t, `resource_metadata="http://[^"]+/prm-403/\.well-known/oauth-protected-resource"`, got)
	})

	t.Run("PRM disabled — no resource_metadata on 403", func(t *testing.T) {
		doc := newOAuth2PRMOAS("/prm-off/", &oas.OAuth2PRM{Enabled: false}, &oas.OAuth2ScopeCheck{
			Enabled:     true,
			ScopeSource: oas.OAuth2ScopeSourceGlobal,
		})
		doc.Security = append(doc.Security, openapi3.SecurityRequirement{"corpOAuth": {"users:read"}})
		loadOAuth2PRMAPI(ts, "/prm-off/", doc)

		token := makeUnverifiedJWT(t, jwt.MapClaims{"scope": "openid"})
		ts.Run(t, test.TestCase{
			Method:  http.MethodGet,
			Path:    "/prm-off/anything",
			Headers: map[string]string{"Authorization": "Bearer " + token},
			Code:    http.StatusForbidden,
			HeadersMatch: map[string]string{
				header.WWWAuthenticate: `Bearer error="insufficient_scope", error_description="missing required scope: users:read", scope="users:read"`,
			},
		})
	})
}
