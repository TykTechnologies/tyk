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

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/httpctx"
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

func TestOAuth2_GlobalScopeAlternatives(t *testing.T) {
	cases := []struct {
		name     string
		scope    *oas.OAuth2ScopeCheck
		expected [][]string
	}{
		{"nil config", nil, nil},
		{"empty config", &oas.OAuth2ScopeCheck{}, nil},
		{
			"global with one alternative",
			&oas.OAuth2ScopeCheck{ScopeSource: oas.OAuth2ScopeSourceGlobal, Scopes: [][]string{{"read", "write"}}},
			[][]string{{"read", "write"}},
		},
		{
			"union with one alternative",
			&oas.OAuth2ScopeCheck{ScopeSource: oas.OAuth2ScopeSourceUnion, Scopes: [][]string{{"a", "b"}}},
			[][]string{{"a", "b"}},
		},
		{
			"empty scopeSource defaults to union",
			&oas.OAuth2ScopeCheck{Scopes: [][]string{{"x"}}},
			[][]string{{"x"}},
		},
		{
			"operation suppresses global",
			&oas.OAuth2ScopeCheck{ScopeSource: oas.OAuth2ScopeSourceOperation, Scopes: [][]string{{"x"}}},
			nil,
		},
		{
			"OR across alternatives — order preserved (first is cited on challenge)",
			&oas.OAuth2ScopeCheck{Scopes: [][]string{{"api:access"}, {"admin"}}},
			[][]string{{"api:access"}, {"admin"}},
		},
		{
			"OR-of-AND general case — inner dedup preserves declared order, outer order preserved",
			&oas.OAuth2ScopeCheck{Scopes: [][]string{{"b", "a", "b", ""}, {"admin"}}},
			// Inner order matches authoring: "b" first, "a" second; second "b"
			// and the empty entry drop. This is what the operator sees on
			// the failure challenge — sorting would silently rewrite their
			// declared form.
			[][]string{{"b", "a"}, {"admin"}},
		},
		{
			"empty inner alternative drops out",
			&oas.OAuth2ScopeCheck{Scopes: [][]string{{}, {"x"}}},
			[][]string{{"x"}},
		},
		{
			"all-empty is inert",
			&oas.OAuth2ScopeCheck{Scopes: [][]string{{""}, {}}},
			nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, globalScopeAlternatives(tc.scope))
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

func newOAuth2GlobalScopeCheckOAS(listenPath string, scopeAlternatives [][]string) oas.OAS {
	doc := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info:    &openapi3.Info{Title: "oauth2-scope-check", Version: "1.0"},
			Paths:   openapi3.NewPaths(),
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
					"corpOAuth": &oas.OAuth2{
						Enabled: true,
						ScopeCheck: &oas.OAuth2ScopeCheck{
							Enabled:     true,
							ScopeSource: oas.OAuth2ScopeSourceGlobal,
							Scopes:      scopeAlternatives,
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

// ----------------------------------------------------------------------------
// Per-operation / per-MCP-primitive scope check
// ----------------------------------------------------------------------------

func TestOAuth2_DedupPreserveOrder(t *testing.T) {
	assert.Nil(t, dedupPreserveOrder(nil))
	assert.Nil(t, dedupPreserveOrder([]string{"", ""}))
	assert.Equal(t, []string{"b", "a", "c"}, dedupPreserveOrder([]string{"b", "a", "b", "", "c", "a"}))
}

func TestOAuth2_ScopeSource(t *testing.T) {
	assert.Equal(t, oas.OAuth2ScopeSourceUnion, oauth2ScopeSource(nil))
	assert.Equal(t, oas.OAuth2ScopeSourceUnion, oauth2ScopeSource(&oas.OAuth2{}))
	assert.Equal(t, oas.OAuth2ScopeSourceUnion, oauth2ScopeSource(&oas.OAuth2{ScopeCheck: &oas.OAuth2ScopeCheck{ScopeSource: "bogus"}}))
	assert.Equal(t, oas.OAuth2ScopeSourceGlobal, oauth2ScopeSource(&oas.OAuth2{ScopeCheck: &oas.OAuth2ScopeCheck{ScopeSource: oas.OAuth2ScopeSourceGlobal}}))
	assert.Equal(t, oas.OAuth2ScopeSourceOperation, oauth2ScopeSource(&oas.OAuth2{ScopeCheck: &oas.OAuth2ScopeCheck{ScopeSource: oas.OAuth2ScopeSourceOperation}}))
}

func TestOAuth2_AppendOAuth2Alternatives(t *testing.T) {
	names := map[string]struct{}{"corpOAuth": {}}
	reqs := openapi3.SecurityRequirements{
		{"corpOAuth": {"users:write", "audit:write"}},
		{"corpOAuth": {"admin"}},
		{"jwtAuth": {}}, // referenced by another scheme — contributes the empty AND-group
	}
	got := appendOAuth2Alternatives(nil, reqs, names)
	require.Len(t, got, 3)
	assert.Equal(t, []string{"users:write", "audit:write"}, got[0])
	assert.Equal(t, []string{"admin"}, got[1])
	assert.Nil(t, got[2])
}

// oauth2PerOpMW builds an OAuth2Middleware backed by an in-memory OAS
// doc with a single oauth2 scheme ("corpOAuth"), the given scopeSource
// and global Scopes, and listen path "/". Caller mutates doc.Paths /
// the middleware block for per-op / per-primitive scenarios.
func oauth2PerOpMW(scopeSource string, globalScopes [][]string) (*OAuth2Middleware, *oas.OAS) {
	doc := oas.OAS{T: openapi3.T{
		OpenAPI: "3.0.3",
		Info:    &openapi3.Info{Title: "per-op", Version: "1.0"},
		Paths:   openapi3.NewPaths(),
	}}
	sc := &oas.OAuth2ScopeCheck{Enabled: true, ScopeSource: scopeSource}
	if len(globalScopes) > 0 {
		sc.Scopes = globalScopes
	}
	doc.SetTykExtension(&oas.XTykAPIGateway{
		Server: oas.Server{
			Authentication: &oas.Authentication{
				Enabled: true,
				SecuritySchemes: oas.SecuritySchemes{
					"corpOAuth": &oas.OAuth2{Enabled: true, ScopeCheck: sc},
				},
			},
			ListenPath: oas.ListenPath{Value: "/", Strip: true},
		},
		Middleware: &oas.Middleware{},
	})
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.IsOAS = true
	spec.OAS = doc
	spec.Proxy.ListenPath = "/"
	return &OAuth2Middleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}, &spec.OAS
}

func reqWithPrimitive(method, path, primitiveName string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	if primitiveName != "" {
		httpctx.SetJSONRPCRoutingState(r, &httpctx.JSONRPCRoutingState{PrimitiveName: primitiveName})
	}
	return r
}

func secReq(scopes ...string) openapi3.SecurityRequirement {
	return openapi3.SecurityRequirement{"corpOAuth": scopes}
}

func TestOAuth2_RequiredScopeAlternatives_RESTOperation(t *testing.T) {
	mw, doc := oauth2PerOpMW(oas.OAuth2ScopeSourceOperation, nil)
	doc.Paths.Set("/users", &openapi3.PathItem{
		Get: &openapi3.Operation{
			Security:  &openapi3.SecurityRequirements{secReq("users:read")},
			Responses: openapi3.NewResponses(),
		},
		Post: &openapi3.Operation{
			Security:  &openapi3.SecurityRequirements{secReq("users:write"), secReq("users:all")},
			Responses: openapi3.NewResponses(),
		},
	})
	doc.Paths.Set("/open", &openapi3.PathItem{Get: &openapi3.Operation{Responses: openapi3.NewResponses()}})

	assert.Equal(t, [][]string{{"users:read"}}, mw.requiredScopeAlternativesForRequest(httptest.NewRequest(http.MethodGet, "/users", nil)))
	assert.Equal(t, [][]string{{"users:write"}, {"users:all"}}, mw.requiredScopeAlternativesForRequest(httptest.NewRequest(http.MethodPost, "/users", nil)))
	// Operation without `security:` → nothing enforced under "operation".
	assert.Nil(t, mw.requiredScopeAlternativesForRequest(httptest.NewRequest(http.MethodGet, "/open", nil)))
	// Unmatched path → nothing enforced.
	assert.Nil(t, mw.requiredScopeAlternativesForRequest(httptest.NewRequest(http.MethodGet, "/missing", nil)))
}

func TestOAuth2_RequiredScopeAlternatives_MCPPrimitive(t *testing.T) {
	mw, doc := oauth2PerOpMW(oas.OAuth2ScopeSourceOperation, nil)
	doc.GetTykMiddleware().McpTools = oas.MCPPrimitives{
		"create_user": {Security: openapi3.SecurityRequirements{secReq("users:write"), secReq("users:all")}},
	}
	doc.GetTykMiddleware().McpResources = oas.MCPPrimitives{
		"file": {Security: openapi3.SecurityRequirements{secReq("files:read")}},
	}

	assert.Equal(t, [][]string{{"users:write"}, {"users:all"}},
		mw.requiredScopeAlternativesForRequest(reqWithPrimitive(http.MethodPost, "/", "create_user")))
	assert.Equal(t, [][]string{{"files:read"}},
		mw.requiredScopeAlternativesForRequest(reqWithPrimitive(http.MethodPost, "/", "file")))
	// Non-tools/call (no primitive name) → nothing enforced.
	assert.Nil(t, mw.requiredScopeAlternativesForRequest(reqWithPrimitive(http.MethodPost, "/", "")))
	// Undeclared primitive → nothing enforced (no security: array).
	assert.Nil(t, mw.requiredScopeAlternativesForRequest(reqWithPrimitive(http.MethodPost, "/", "delete_user")))
}

func TestOAuth2_RequiredScopeAlternatives_UnionAndOperationAndGlobal(t *testing.T) {
	t.Run("union ANDs the global baseline onto each per-op alternative", func(t *testing.T) {
		mw, doc := oauth2PerOpMW(oas.OAuth2ScopeSourceUnion, [][]string{{"api:access"}})
		doc.Paths.Set("/users", &openapi3.PathItem{Get: &openapi3.Operation{
			Security:  &openapi3.SecurityRequirements{secReq("users:read"), secReq("users:all")},
			Responses: openapi3.NewResponses(),
		}})
		assert.Equal(t, [][]string{{"users:read", "api:access"}, {"users:all", "api:access"}},
			mw.requiredScopeAlternativesForRequest(httptest.NewRequest(http.MethodGet, "/users", nil)))
	})
	t.Run("union with no per-op security falls back to the global list", func(t *testing.T) {
		mw, doc := oauth2PerOpMW(oas.OAuth2ScopeSourceUnion, [][]string{{"api:access"}})
		doc.Paths.Set("/open", &openapi3.PathItem{Get: &openapi3.Operation{Responses: openapi3.NewResponses()}})
		assert.Equal(t, [][]string{{"api:access"}},
			mw.requiredScopeAlternativesForRequest(httptest.NewRequest(http.MethodGet, "/open", nil)))
	})
	t.Run("operation ignores the global baseline", func(t *testing.T) {
		mw, doc := oauth2PerOpMW(oas.OAuth2ScopeSourceOperation, [][]string{{"api:access"}})
		doc.Paths.Set("/users", &openapi3.PathItem{Get: &openapi3.Operation{
			Security:  &openapi3.SecurityRequirements{secReq("users:read")},
			Responses: openapi3.NewResponses(),
		}})
		assert.Equal(t, [][]string{{"users:read"}},
			mw.requiredScopeAlternativesForRequest(httptest.NewRequest(http.MethodGet, "/users", nil)))
	})
	t.Run("global ignores per-op security", func(t *testing.T) {
		mw, doc := oauth2PerOpMW(oas.OAuth2ScopeSourceGlobal, [][]string{{"api:access"}})
		doc.Paths.Set("/users", &openapi3.PathItem{Get: &openapi3.Operation{
			Security:  &openapi3.SecurityRequirements{secReq("users:read")},
			Responses: openapi3.NewResponses(),
		}})
		assert.Equal(t, [][]string{{"api:access"}},
			mw.requiredScopeAlternativesForRequest(httptest.NewRequest(http.MethodGet, "/users", nil)))
	})
}

// newOAuth2PerOpScopeCheckOAS builds an OAS API for end-to-end
// per-operation scope-check tests: one path "/users" with GET and POST
// operations carrying `security:` arrays for the "corpOAuth" oauth2
// scheme.
func newOAuth2PerOpScopeCheckOAS(listenPath, scopeSource string, globalScopes [][]string) oas.OAS {
	doc := oas.OAS{T: openapi3.T{
		OpenAPI: "3.0.3",
		Info:    &openapi3.Info{Title: "oauth2-per-op", Version: "1.0"},
		Paths:   openapi3.NewPaths(),
	}}
	doc.Paths.Set("/users", &openapi3.PathItem{
		Get: &openapi3.Operation{
			Security:  &openapi3.SecurityRequirements{secReq("users:read")},
			Responses: openapi3.NewResponses(),
		},
		Post: &openapi3.Operation{
			Security:  &openapi3.SecurityRequirements{secReq("users:write"), secReq("users:all")},
			Responses: openapi3.NewResponses(),
		},
	})
	doc.Paths.Set("/open", &openapi3.PathItem{Get: &openapi3.Operation{Responses: openapi3.NewResponses()}})
	sc := &oas.OAuth2ScopeCheck{Enabled: true, ScopeSource: scopeSource}
	if len(globalScopes) > 0 {
		sc.Scopes = globalScopes
	}
	doc.SetTykExtension(&oas.XTykAPIGateway{
		Info:     oas.Info{Name: "oauth2-per-op", State: oas.State{Active: true}},
		Upstream: oas.Upstream{URL: TestHttpAny},
		Server: oas.Server{
			ListenPath: oas.ListenPath{Value: listenPath, Strip: true},
			Authentication: &oas.Authentication{
				Enabled: true,
				SecuritySchemes: oas.SecuritySchemes{
					"corpOAuth": &oas.OAuth2{Enabled: true, ScopeCheck: sc},
				},
			},
		},
	})
	return doc
}

func TestOAuth2Middleware_PerOperationScopeCheck_EndToEnd(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	loadAPI := func(listenPath, source string, global [][]string) {
		doc := newOAuth2PerOpScopeCheckOAS(listenPath, source, global)
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = listenPath
			spec.IsOAS = true
			spec.OAS = doc
		})
	}
	bearer := func(scopes string) map[string]string {
		return map[string]string{"Authorization": "Bearer " + makeUnverifiedJWT(t, jwt.MapClaims{"scope": scopes})}
	}

	t.Run("operation source — token has the operation scope", func(t *testing.T) {
		loadAPI("/op1/", oas.OAuth2ScopeSourceOperation, nil)
		ts.Run(t, test.TestCase{Method: http.MethodGet, Path: "/op1/users", Headers: bearer("users:read"), Code: http.StatusOK})
	})
	t.Run("operation source — token missing the operation scope → 403 cites it", func(t *testing.T) {
		loadAPI("/op2/", oas.OAuth2ScopeSourceOperation, nil)
		ts.Run(t, test.TestCase{
			Method: http.MethodGet, Path: "/op2/users", Headers: bearer("other"), Code: http.StatusForbidden,
			BodyMatch: `"error":"insufficient_scope".*"scope":"users:read"`,
			HeadersMatch: map[string]string{
				header.WWWAuthenticate: `Bearer error="insufficient_scope", error_description="missing required scope: users:read", scope="users:read"`,
			},
		})
	})
	t.Run("operation source — OR-of-AND alternatives", func(t *testing.T) {
		loadAPI("/op3/", oas.OAuth2ScopeSourceOperation, nil)
		ts.Run(t, test.TestCase{Method: http.MethodPost, Path: "/op3/users", Headers: bearer("users:write"), Code: http.StatusOK})
		ts.Run(t, test.TestCase{Method: http.MethodPost, Path: "/op3/users", Headers: bearer("users:all"), Code: http.StatusOK})
		ts.Run(t, test.TestCase{Method: http.MethodPost, Path: "/op3/users", Headers: bearer("users:write users:all"), Code: http.StatusOK})
		ts.Run(t, test.TestCase{
			Method: http.MethodPost, Path: "/op3/users", Headers: bearer("users:read"), Code: http.StatusForbidden,
			BodyMatch:    `"scope":"users:write"`,
			BodyNotMatch: `users:all`,
		})
	})
	t.Run("operation source — operation with no security: is not enforced", func(t *testing.T) {
		loadAPI("/op4/", oas.OAuth2ScopeSourceOperation, [][]string{{"api:access"}})
		ts.Run(t, test.TestCase{Method: http.MethodGet, Path: "/op4/open", Code: http.StatusOK})
	})
	t.Run("union source — per-op AND global baseline both enforced", func(t *testing.T) {
		loadAPI("/op5/", oas.OAuth2ScopeSourceUnion, [][]string{{"api:access"}})
		ts.Run(t, test.TestCase{Method: http.MethodGet, Path: "/op5/users", Headers: bearer("api:access users:read"), Code: http.StatusOK})
		ts.Run(t, test.TestCase{Method: http.MethodGet, Path: "/op5/users", Headers: bearer("api:access"), Code: http.StatusForbidden})
		ts.Run(t, test.TestCase{Method: http.MethodGet, Path: "/op5/users", Headers: bearer("users:read"), Code: http.StatusForbidden})
	})
	t.Run("operation source — global baseline ignored", func(t *testing.T) {
		loadAPI("/op6/", oas.OAuth2ScopeSourceOperation, [][]string{{"api:access"}})
		ts.Run(t, test.TestCase{Method: http.MethodGet, Path: "/op6/users", Headers: bearer("users:read"), Code: http.StatusOK})
	})
	t.Run("global source — per-op ignored", func(t *testing.T) {
		loadAPI("/op7/", oas.OAuth2ScopeSourceGlobal, [][]string{{"api:access"}})
		ts.Run(t, test.TestCase{Method: http.MethodGet, Path: "/op7/users", Headers: bearer("api:access"), Code: http.StatusOK})
	})
}
