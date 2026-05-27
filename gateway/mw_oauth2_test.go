package gateway

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
)

// ----------------------------------------------------------------------------
// Pure-function helpers
// ----------------------------------------------------------------------------

func TestOAuth2_SplitNonEmpty(t *testing.T) {
	assert.Nil(t, splitNonEmptyOrNil(splitNonEmpty("", " ")))
	assert.Equal(t, []string{"a", "b"}, splitNonEmpty("a b", " "))
	assert.Equal(t, []string{"a", "b"}, splitNonEmpty("a, b", ","))
	assert.Equal(t, []string{"a"}, splitNonEmpty(" a ", " "))
	assert.Equal(t, []string{"a", "b"}, splitNonEmpty("a  b", " "), "double-space tolerated")
}

func splitNonEmptyOrNil(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	return in
}

func TestOAuth2_ExtractScopes(t *testing.T) {
	t.Run("string claim with default separator", func(t *testing.T) {
		got := extractScopes(jwt.MapClaims{"scope": "read write"}, "scope", " ")
		assert.Equal(t, []string{"read", "write"}, got)
	})

	t.Run("string claim with custom separator", func(t *testing.T) {
		got := extractScopes(jwt.MapClaims{"scope": "read,write"}, "scope", ",")
		assert.Equal(t, []string{"read", "write"}, got)
	})

	t.Run("array of interface", func(t *testing.T) {
		got := extractScopes(jwt.MapClaims{"scope": []interface{}{"read", "write", ""}}, "scope", " ")
		assert.Equal(t, []string{"read", "write"}, got)
	})

	t.Run("array of string", func(t *testing.T) {
		got := extractScopes(jwt.MapClaims{"scope": []string{"read", "write"}}, "scope", " ")
		assert.Equal(t, []string{"read", "write"}, got)
	})

	t.Run("absent claim returns nil", func(t *testing.T) {
		got := extractScopes(jwt.MapClaims{}, "scope", " ")
		assert.Nil(t, got)
	})

	t.Run("non-stringy claim returns nil", func(t *testing.T) {
		got := extractScopes(jwt.MapClaims{"scope": 42}, "scope", " ")
		assert.Nil(t, got)
	})
}

func TestOAuth2_ScopeClaimCandidates(t *testing.T) {
	t.Run("nil config falls back to default scope/scp", func(t *testing.T) {
		assert.Equal(t, []string{"scope", "scp"}, scopeClaimCandidates(nil))
	})

	t.Run("empty ClaimNames falls back to default", func(t *testing.T) {
		assert.Equal(t, []string{"scope", "scp"}, scopeClaimCandidates(&oas.OAuth2ScopeCheck{}))
	})

	t.Run("operator-supplied ClaimNames is used verbatim", func(t *testing.T) {
		got := scopeClaimCandidates(&oas.OAuth2ScopeCheck{ClaimNames: []string{"permissions", "scope"}})
		assert.Equal(t, []string{"permissions", "scope"}, got)
	})
}

// TestOAuth2_LookupScopes_MergesAcrossClaims pins the merge semantics:
// values from every listed claim contribute to a single deduplicated
// scope set. There is no first-non-empty-wins precedence.
func TestOAuth2_LookupScopes_MergesAcrossClaims(t *testing.T) {
	sc := &oas.OAuth2ScopeCheck{ClaimNames: []string{"scope", "scp"}}

	t.Run("merges scope and scp into one set", func(t *testing.T) {
		claims := jwt.MapClaims{
			"scope": "read",
			"scp":   []interface{}{"write"},
		}
		got := lookupScopes(claims, sc, " ")
		assert.ElementsMatch(t, []string{"read", "write"}, got)
	})

	t.Run("dedups across claims", func(t *testing.T) {
		claims := jwt.MapClaims{
			"scope": "read write",
			"scp":   []interface{}{"write", "delete"},
		}
		got := lookupScopes(claims, sc, " ")
		assert.ElementsMatch(t, []string{"read", "write", "delete"}, got)
	})

	t.Run("missing claim contributes nothing", func(t *testing.T) {
		got := lookupScopes(jwt.MapClaims{"scope": "read"}, sc, " ")
		assert.Equal(t, []string{"read"}, got)
	})

	t.Run("default fallback honors both scope and scp claims", func(t *testing.T) {
		claims := jwt.MapClaims{
			"scope": "read",
			"scp":   "write",
		}
		got := lookupScopes(claims, &oas.OAuth2ScopeCheck{}, " ")
		assert.ElementsMatch(t, []string{"read", "write"}, got)
	})
}

func TestOAuth2_RootSecurityAlternatives(t *testing.T) {
	req := func(scheme string, scopes ...string) openapi3.SecurityRequirement {
		out := openapi3.NewSecurityRequirement()
		out[scheme] = append([]string{}, scopes...)
		return out
	}

	cases := []struct {
		name     string
		security openapi3.SecurityRequirements
		scheme   string
		sc       *oas.OAuth2ScopeCheck
		expected [][]string
	}{
		{"nil config", nil, "oauth2", nil, nil},
		{"empty scheme name", openapi3.SecurityRequirements{req("oauth2", "x")}, "", &oas.OAuth2ScopeCheck{}, nil},
		{"empty security", nil, "oauth2", &oas.OAuth2ScopeCheck{}, nil},
		{
			"global mode reads root security",
			openapi3.SecurityRequirements{req("oauth2", "read", "write")},
			"oauth2",
			&oas.OAuth2ScopeCheck{ScopeSource: oas.OAuth2ScopeSourceGlobal},
			[][]string{{"read", "write"}},
		},
		{
			"union mode reads root security",
			openapi3.SecurityRequirements{req("oauth2", "a", "b")},
			"oauth2",
			&oas.OAuth2ScopeCheck{ScopeSource: oas.OAuth2ScopeSourceUnion},
			[][]string{{"a", "b"}},
		},
		{
			"empty scopeSource defaults to union",
			openapi3.SecurityRequirements{req("oauth2", "x")},
			"oauth2",
			&oas.OAuth2ScopeCheck{},
			[][]string{{"x"}},
		},
		{
			"operation suppresses root security",
			openapi3.SecurityRequirements{req("oauth2", "x")},
			"oauth2",
			&oas.OAuth2ScopeCheck{ScopeSource: oas.OAuth2ScopeSourceOperation},
			nil,
		},
		{
			"OR across requirements — declared order preserved (first cited on failure)",
			openapi3.SecurityRequirements{req("oauth2", "api:access"), req("oauth2", "admin")},
			"oauth2",
			&oas.OAuth2ScopeCheck{},
			[][]string{{"api:access"}, {"admin"}},
		},
		{
			"OR-of-AND general — inner dedup preserves declared order",
			openapi3.SecurityRequirements{req("oauth2", "b", "a", "b", ""), req("oauth2", "admin")},
			"oauth2",
			&oas.OAuth2ScopeCheck{},
			[][]string{{"b", "a"}, {"admin"}},
		},
		{
			"requirements that don't reference the scheme drop out",
			openapi3.SecurityRequirements{req("jwtAuth", "x"), req("oauth2", "y")},
			"oauth2",
			&oas.OAuth2ScopeCheck{},
			[][]string{{"y"}},
		},
		{
			"empty scope list on the scheme is preserved — vacuously satisfied per OAS",
			openapi3.SecurityRequirements{req("oauth2")},
			"oauth2",
			&oas.OAuth2ScopeCheck{},
			[][]string{{}},
		},
		{
			// Pins the name-agnostic contract. OpenAPI 3.x lets the
			// operator name security schemes freely; the helper must
			// filter strictly by the supplied schemeName and ignore
			// every other key, including ones that look oauth2-ish
			// (e.g. literal "oauth2"). The shape under the key is data.
			"filters strictly by the supplied scheme name (custom name with mixed casing)",
			openapi3.SecurityRequirements{
				req("oauth2", "ignored"),
				req("prctOauth", "abc", "def"),
				req("jwtAuth", "ignored-too"),
				req("prctOauth", "ghi"),
			},
			"prctOauth",
			&oas.OAuth2ScopeCheck{},
			[][]string{{"abc", "def"}, {"ghi"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, rootSecurityAlternatives(tc.security, tc.scheme, tc.sc))
		})
	}
}

func TestOAuth2_TokenSatisfiesAnyAlternative(t *testing.T) {
	sc := &oas.OAuth2ScopeCheck{ClaimNames: []string{"scope", "scp"}}

	t.Run("single alternative — all required present passes", func(t *testing.T) {
		claims := jwt.MapClaims{"scope": "read write delete"}
		assert.True(t, tokenSatisfiesAnyAlternative(claims, sc, [][]string{{"read", "write"}}))
	})

	t.Run("single alternative — missing one scope fails", func(t *testing.T) {
		claims := jwt.MapClaims{"scope": "read"}
		assert.False(t, tokenSatisfiesAnyAlternative(claims, sc, [][]string{{"read", "write"}}))
	})

	t.Run("scopes spread across claims pass", func(t *testing.T) {
		claims := jwt.MapClaims{"scope": "read", "scp": []interface{}{"write"}}
		assert.True(t, tokenSatisfiesAnyAlternative(claims, sc, [][]string{{"read", "write"}}))
	})

	t.Run("OR — second alternative satisfied passes", func(t *testing.T) {
		claims := jwt.MapClaims{"scope": "admin"}
		assert.True(t, tokenSatisfiesAnyAlternative(claims, sc, [][]string{{"api:access"}, {"admin"}}))
	})

	t.Run("OR — neither alternative satisfied fails", func(t *testing.T) {
		claims := jwt.MapClaims{"scope": "other"}
		assert.False(t, tokenSatisfiesAnyAlternative(claims, sc, [][]string{{"api:access"}, {"admin"}}))
	})

	t.Run("OR-of-AND — first alternative (AND of two) satisfied passes", func(t *testing.T) {
		claims := jwt.MapClaims{"scope": "api:access tenant:read"}
		assert.True(t, tokenSatisfiesAnyAlternative(claims, sc, [][]string{{"api:access", "tenant:read"}, {"admin"}}))
	})

	t.Run("OR-of-AND — first AND partial, second OR alone satisfies", func(t *testing.T) {
		claims := jwt.MapClaims{"scope": "api:access admin"}
		assert.True(t, tokenSatisfiesAnyAlternative(claims, sc, [][]string{{"api:access", "tenant:read"}, {"admin"}}))
	})

	t.Run("OR-of-AND — partial coverage of both alternatives fails", func(t *testing.T) {
		claims := jwt.MapClaims{"scope": "api:access"}
		assert.False(t, tokenSatisfiesAnyAlternative(claims, sc, [][]string{{"api:access", "tenant:read"}, {"admin"}}))
	})
}

// ----------------------------------------------------------------------------
// WWW-Authenticate header shape — RFC 6750 §3
// ----------------------------------------------------------------------------

// rfc6750BearerHeader pins the on-the-wire form: scheme `Bearer`,
// SP, then comma-delimited auth-params with quoted values. We shipped
// `Bearer, error=...` in a past regression, so this regex assertion is
// load-bearing and cannot be relaxed.
var rfc6750BearerHeader = regexp.MustCompile(`^Bearer ([a-z_]+="[^"]*")(, [a-z_]+="[^"]*")*$`)

func TestOAuth2_SetWWWAuthenticateInsufficientScope_HeaderShape(t *testing.T) {
	m := &OAuth2Middleware{}
	w := httptest.NewRecorder()
	m.setWWWAuthenticateInsufficientScope(w, []string{"read:billing", "write:billing"})

	got := w.Header().Get(header.WWWAuthenticate)
	require.True(t, rfc6750BearerHeader.MatchString(got), "header %q must match RFC 6750 §3 form", got)
	assert.Contains(t, got, `error="insufficient_scope"`)
	assert.Contains(t, got, `scope="read:billing write:billing"`)
	assert.Contains(t, got, `error_description="missing required scope: read:billing write:billing"`)
}

func TestOAuth2_SetWWWAuthenticateInsufficientToken_HeaderShape(t *testing.T) {
	m := &OAuth2Middleware{}
	w := httptest.NewRecorder()
	m.setWWWAuthenticateInsufficientToken(w, oas.OAuth2ErrInvalidToken, "missing bearer token")

	got := w.Header().Get(header.WWWAuthenticate)
	require.True(t, rfc6750BearerHeader.MatchString(got), "header %q must match RFC 6750 §3 form", got)
	assert.Contains(t, got, `error="invalid_token"`)
	assert.Contains(t, got, `error_description="missing bearer token"`)
}

// ----------------------------------------------------------------------------
// End-to-end via StartTest — global scope check enforcement
// ----------------------------------------------------------------------------

// makeUnverifiedJWT signs a JWT with the supplied claims using HS256
// and a fixed test secret. Signature is not verified by the oauth2
// middleware (it reads claims unverified — JWT signature verification
// is the JWT middleware's job).
func makeUnverifiedJWT(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte("test-secret"))
	require.NoError(t, err)
	return signed
}

// newOAuth2GlobalScopeCheckOAS builds an OAS document with a single
// OAS-native oauth2 scheme named "corpOAuth" and the supplied required
// scopes expressed as OAS root `security:` Security Requirement
// Objects. Each inner slice is one Security Requirement (AND across
// its scopes); outer entries are OR alternatives. The scheme is also
// declared in Components.SecuritySchemes so the document validates
// against the OAS spec.
func newOAuth2GlobalScopeCheckOAS(listenPath string, scopeAlternatives [][]string) oas.OAS {
	return newOAuth2GlobalScopeCheckOASNamed(listenPath, "corpOAuth", scopeAlternatives)
}

// newOAuth2GlobalScopeCheckOASNamed is the name-parameterised variant.
// OpenAPI 3.x lets the operator name security schemes freely, so the
// middleware contract is name-agnostic — this helper lets the test
// suite exercise that contract under non-default names.
func newOAuth2GlobalScopeCheckOASNamed(listenPath, schemeName string, scopeAlternatives [][]string) oas.OAS {
	security := openapi3.SecurityRequirements{}
	for _, alt := range scopeAlternatives {
		req := openapi3.NewSecurityRequirement()
		req[schemeName] = append([]string{}, alt...)
		security = append(security, req)
	}
	doc := oas.OAS{
		T: openapi3.T{
			OpenAPI:  "3.0.3",
			Info:     &openapi3.Info{Title: "oauth2-scope-check", Version: "1.0"},
			Paths:    openapi3.NewPaths(),
			Security: security,
			Components: &openapi3.Components{
				SecuritySchemes: openapi3.SecuritySchemes{
					schemeName: &openapi3.SecuritySchemeRef{
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
		Info: oas.Info{
			Name:  "oauth2-scope-check",
			State: oas.State{Active: true},
		},
		Upstream: oas.Upstream{URL: TestHttpAny},
		Server: oas.Server{
			ListenPath: oas.ListenPath{Value: listenPath, Strip: true},
			Authentication: &oas.Authentication{
				Enabled: true,
				SecuritySchemes: oas.SecuritySchemes{
					schemeName: &oas.OAuth2{
						Enabled: true,
						ScopeCheck: &oas.OAuth2ScopeCheck{
							Enabled:     true,
							ScopeSource: oas.OAuth2ScopeSourceGlobal,
						},
					},
				},
			},
		},
	})
	return doc
}

func TestOAuth2Middleware_GlobalScopeCheck_EndToEnd(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	doc := newOAuth2GlobalScopeCheckOAS("/scope/", [][]string{{"read:billing", "write:billing"}})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/scope/"
		spec.IsOAS = true
		spec.OAS = doc
	})

	t.Run("token with required scopes passes", func(t *testing.T) {
		token := makeUnverifiedJWT(t, jwt.MapClaims{"scope": "read:billing write:billing"})
		ts.Run(t, test.TestCase{
			Method:  http.MethodGet,
			Path:    "/scope/anything",
			Headers: map[string]string{"Authorization": "Bearer " + token},
			Code:    http.StatusOK,
		})
	})

	t.Run("token missing one scope fails 403 with insufficient_scope challenge", func(t *testing.T) {
		token := makeUnverifiedJWT(t, jwt.MapClaims{"scope": "read:billing"})
		ts.Run(t, test.TestCase{
			Method:  http.MethodGet,
			Path:    "/scope/anything",
			Headers: map[string]string{"Authorization": "Bearer " + token},
			Code:    http.StatusForbidden,
			// JSON body shape — `error_description` is space-joined,
			// not Go-slice-formatted (`[read:billing write:billing]`).
			// `scope` matches the header-side advertised set verbatim.
			BodyMatch: `"error":"insufficient_scope","error_description":"token does not satisfy required scopes: read:billing write:billing","scope":"read:billing write:billing"`,
			HeadersMatch: map[string]string{
				header.WWWAuthenticate: `Bearer error="insufficient_scope", error_description="missing required scope: read:billing write:billing", scope="read:billing write:billing"`,
			},
		})
	})

	t.Run("scopes spread across scope and scp claims pass", func(t *testing.T) {
		token := makeUnverifiedJWT(t, jwt.MapClaims{
			"scope": "read:billing",
			"scp":   []string{"write:billing"},
		})
		ts.Run(t, test.TestCase{
			Method:  http.MethodGet,
			Path:    "/scope/anything",
			Headers: map[string]string{"Authorization": "Bearer " + token},
			Code:    http.StatusOK,
		})
	})

	t.Run("missing token fails 401 with invalid_token challenge", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Method: http.MethodGet,
			Path:   "/scope/anything",
			Code:   http.StatusUnauthorized,
			HeadersMatch: map[string]string{
				header.WWWAuthenticate: `Bearer error="invalid_token", error_description="missing bearer token"`,
			},
		})
	})

	t.Run("malformed token fails 401 with invalid_token challenge", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Method:  http.MethodGet,
			Path:    "/scope/anything",
			Headers: map[string]string{"Authorization": "Bearer not-a-jwt"},
			Code:    http.StatusUnauthorized,
			HeadersMatch: map[string]string{
				header.WWWAuthenticate: `Bearer error="invalid_token", error_description="token is not a parseable JWT"`,
			},
		})
	})
}

// TestOAuth2Middleware_DisabledScopeCheck_NoEnforcement verifies the
// middleware short-circuits when scopeCheck is not enabled — the
// request is not gated even if no token is presented.
func TestOAuth2Middleware_DisabledScopeCheck_NoEnforcement(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	doc := newOAuth2GlobalScopeCheckOAS("/scope-off/", [][]string{{"read"}})
	cfg := doc.GetTykExtension().Server.Authentication.SecuritySchemes["corpOAuth"].(*oas.OAuth2)
	cfg.ScopeCheck.Enabled = false

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/scope-off/"
		spec.IsOAS = true
		spec.OAS = doc
	})

	ts.Run(t, test.TestCase{
		Method: http.MethodGet,
		Path:   "/scope-off/anything",
		Code:   http.StatusOK,
	})
}

// TestOAuth2Middleware_EmptyRequiredScopes_NoEnforcement verifies the
// middleware short-circuits when scopeCheck is enabled but the global
// path has nothing to enforce (RequiredScopes empty under
// global/union).
func TestOAuth2Middleware_EmptyRequiredScopes_NoEnforcement(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	doc := newOAuth2GlobalScopeCheckOAS("/scope-empty/", nil)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/scope-empty/"
		spec.IsOAS = true
		spec.OAS = doc
	})

	ts.Run(t, test.TestCase{
		Method: http.MethodGet,
		Path:   "/scope-empty/anything",
		Code:   http.StatusOK,
	})
}

// TestOAuth2Middleware_CitedAlternativePreservesDeclaredOrder pins
// that an operator who declared their AND-row scopes in a specific
// order sees that same order on the failure challenge — both in the
// JSON body's `scope` field and in the WWW-Authenticate `scope=`
// parameter. Sorting would silently rewrite their authored form on
// the wire; a past PoC of this middleware did exactly that, so this
// is a regression guard.
func TestOAuth2Middleware_CitedAlternativePreservesDeclaredOrder(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	doc := newOAuth2GlobalScopeCheckOAS("/scope-order/", [][]string{{"write:billing", "read:billing"}})
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/scope-order/"
		spec.IsOAS = true
		spec.OAS = doc
	})

	token := makeUnverifiedJWT(t, jwt.MapClaims{"scope": "openid"})
	ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/scope-order/anything",
		Headers:   map[string]string{"Authorization": "Bearer " + token},
		Code:      http.StatusForbidden,
		BodyMatch: `"scope":"write:billing read:billing"`,
		HeadersMatch: map[string]string{
			header.WWWAuthenticate: `Bearer error="insufficient_scope", error_description="missing required scope: write:billing read:billing", scope="write:billing read:billing"`,
		},
	})
}

// TestOAuth2Middleware_CitesFirstDeclaredAlternativeOnly pins that
// an OR-of-AND policy with multiple alternatives cites ONLY the first
// alternative on the failure challenge — listing every alternative
// would leak intent (e.g. advertising a service-account scope to a
// user-token caller). The behavior is documented as a security
// tradeoff in mw_oauth2.go; this test pins it.
func TestOAuth2Middleware_CitesFirstDeclaredAlternativeOnly(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	doc := newOAuth2GlobalScopeCheckOAS("/scope-or/", [][]string{{"api:access"}, {"admin"}})
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/scope-or/"
		spec.IsOAS = true
		spec.OAS = doc
	})

	token := makeUnverifiedJWT(t, jwt.MapClaims{"scope": "openid"})
	ts.Run(t, test.TestCase{
		Method:       http.MethodGet,
		Path:         "/scope-or/anything",
		Headers:      map[string]string{"Authorization": "Bearer " + token},
		Code:         http.StatusForbidden,
		BodyMatch:    `"scope":"api:access"`,
		BodyNotMatch: `admin`,
		HeadersMatch: map[string]string{
			header.WWWAuthenticate: `Bearer error="insufficient_scope", error_description="missing required scope: api:access", scope="api:access"`,
		},
	})
}

// TestOAuth2Middleware_NameAgnostic pins the contract that enforcement
// works regardless of what the operator named the security scheme in
// OpenAPI components — `prctOauth`, `oauth2`, or any other valid
// identifier. The other end-to-end tests in this file happen to all
// use `corpOAuth`; this test deliberately picks a different name to
// make name-agnosticism an explicit guarantee rather than an incidental
// coincidence of test data. Pair with the dashboard webclient
// `resolveSchemeName` contract — both sides must agree on the name.
func TestOAuth2Middleware_NameAgnostic(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	doc := newOAuth2GlobalScopeCheckOASNamed("/scope-named/", "prctOauth", [][]string{{"abc", "def"}, {"ghi"}})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/scope-named/"
		spec.IsOAS = true
		spec.OAS = doc
	})

	t.Run("token satisfying first AND alternative passes", func(t *testing.T) {
		token := makeUnverifiedJWT(t, jwt.MapClaims{"scope": "abc def"})
		ts.Run(t, test.TestCase{
			Method:  http.MethodGet,
			Path:    "/scope-named/anything",
			Headers: map[string]string{"Authorization": "Bearer " + token},
			Code:    http.StatusOK,
		})
	})

	t.Run("token satisfying second OR alternative passes", func(t *testing.T) {
		token := makeUnverifiedJWT(t, jwt.MapClaims{"scope": "ghi"})
		ts.Run(t, test.TestCase{
			Method:  http.MethodGet,
			Path:    "/scope-named/anything",
			Headers: map[string]string{"Authorization": "Bearer " + token},
			Code:    http.StatusOK,
		})
	})

	t.Run("token satisfying neither alternative fails 403 citing the first one", func(t *testing.T) {
		token := makeUnverifiedJWT(t, jwt.MapClaims{"scope": "unrelated"})
		ts.Run(t, test.TestCase{
			Method:    http.MethodGet,
			Path:      "/scope-named/anything",
			Headers:   map[string]string{"Authorization": "Bearer " + token},
			Code:      http.StatusForbidden,
			BodyMatch: `"scope":"abc def"`,
			HeadersMatch: map[string]string{
				header.WWWAuthenticate: `Bearer error="insufficient_scope", error_description="missing required scope: abc def", scope="abc def"`,
			},
		})
	})
}
