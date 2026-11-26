package gateway

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

const claimsOnlyTestOrg = "default"

// buildJWTTestAPI builds an RSA JWT API identified by the user_id claim. With
// asOAS it is a Tyk OAS API whose JWT scheme can be adjusted through configure.
func buildJWTTestAPI(apiID string, asOAS bool, configure func(jwtConf *oas.JWT)) *APISpec {
	source := base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))

	spec := BuildAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.Name = apiID
		spec.OrgID = claimsOnlyTestOrg
		spec.Proxy.ListenPath = "/" + apiID + "/"
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = source
		spec.JWTIdentityBaseField = "user_id"
	})[0]

	if !asOAS {
		return spec
	}

	jwtConf := &oas.JWT{
		Enabled:           true,
		Source:            source,
		SigningMethod:     RSASign,
		IdentityBaseField: "user_id",
		AuthSources: oas.AuthSources{
			Header: &oas.AuthSource{Enabled: true, Name: "Authorization"},
		},
	}
	if configure != nil {
		configure(jwtConf)
	}

	oasDoc := oas.OAS{T: openapi3.T{
		OpenAPI: "3.0.3",
		Info:    &openapi3.Info{Title: apiID, Version: "1.0.0"},
		Paths:   openapi3.NewPaths(),
		Components: &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"jwtAuth": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{Type: "http", Scheme: "bearer", BearerFormat: "JWT"},
				},
			},
		},
		Security: openapi3.SecurityRequirements{{"jwtAuth": []string{}}},
	}}
	oasDoc.SetTykExtension(&oas.XTykAPIGateway{
		Info: oas.Info{
			ID:    apiID,
			Name:  apiID,
			OrgID: claimsOnlyTestOrg,
			State: oas.State{Active: true},
		},
		Server: oas.Server{
			ListenPath: oas.ListenPath{Value: spec.Proxy.ListenPath, Strip: true},
			Authentication: &oas.Authentication{
				Enabled:         true,
				SecuritySchemes: oas.SecuritySchemes{"jwtAuth": jwtConf},
			},
		},
		Upstream: oas.Upstream{URL: TestHttpAny},
	})

	oasDoc.ExtractTo(spec.APIDefinition)
	spec.IsOAS = true
	spec.OAS = oasDoc

	return spec
}

func blockingClaimRule(values ...interface{}) map[string]oas.CustomClaimValidationConfig {
	return map[string]oas.CustomClaimValidationConfig{
		"client_id": {Type: oas.ClaimValidationTypeExactMatch, AllowedValues: values},
	}
}

func claimsOnlyAPI(apiID string) *APISpec {
	return buildJWTTestAPI(apiID, true, func(jwtConf *oas.JWT) {
		jwtConf.CustomClaimValidation = blockingClaimRule("trusted-client")
	})
}

func jwtWithClaims(claims map[string]interface{}) map[string]string {
	token := CreateJWKToken(func(t *jwt.Token) {
		mapClaims, ok := t.Claims.(jwt.MapClaims)
		if !ok {
			panic("unexpected claims type")
		}
		mapClaims["exp"] = time.Now().Add(time.Hour).Unix()
		for name, value := range claims {
			if value == nil {
				delete(mapClaims, name)
				continue
			}
			mapClaims[name] = value
		}
	})

	return map[string]string{"Authorization": token}
}

func (ts *Test) sharedJWTSessionID(identity string) string {
	return ts.Gw.generateToken(claimsOnlyTestOrg, fmt.Sprintf("%x", md5.Sum([]byte(identity))))
}

func (ts *Test) claimsOnlySessionID(apiID, identity string) string {
	return ts.Gw.generateToken(claimsOnlyTestOrg, claimsOnlySessionKeyID(apiID, identity))
}

func (ts *Test) storedSession(sessionID string) (user.SessionState, bool) {
	return ts.Gw.GlobalSessionManager.SessionDetail(claimsOnlyTestOrg, sessionID, false)
}

func TestJWTClaimsOnly_Detection(t *testing.T) {
	restricting := blockingClaimRule("trusted-client")

	cases := []struct {
		name      string
		classic   bool
		configure func(jwtConf *oas.JWT)
		scopeMap  map[string]string
		expected  bool
	}{
		{
			name:      "blocking exact_match rule",
			configure: func(c *oas.JWT) { c.CustomClaimValidation = restricting },
			expected:  true,
		},
		{
			name: "blocking contains rule with numeric value",
			configure: func(c *oas.JWT) {
				c.CustomClaimValidation = map[string]oas.CustomClaimValidationConfig{
					"tier": {Type: oas.ClaimValidationTypeContains, AllowedValues: []interface{}{float64(0)}},
				}
			},
			expected: true,
		},
		{
			name: "restricting rule next to a non-blocking one",
			configure: func(c *oas.JWT) {
				c.CustomClaimValidation = map[string]oas.CustomClaimValidationConfig{
					"client_id": restricting["client_id"],
					"tier":      {Type: oas.ClaimValidationTypeRequired, NonBlocking: true},
				}
			},
			expected: true,
		},
		{name: "no rules"},
		{
			name: "non-blocking rule",
			configure: func(c *oas.JWT) {
				c.CustomClaimValidation = map[string]oas.CustomClaimValidationConfig{
					"client_id": {Type: oas.ClaimValidationTypeExactMatch, AllowedValues: []interface{}{"a"}, NonBlocking: true},
				}
			},
		},
		{
			name: "required rule",
			configure: func(c *oas.JWT) {
				c.CustomClaimValidation = map[string]oas.CustomClaimValidationConfig{
					"client_id": {Type: oas.ClaimValidationTypeRequired},
				}
			},
		},
		{
			name:      "no allowed values",
			configure: func(c *oas.JWT) { c.CustomClaimValidation = blockingClaimRule() },
		},
		{
			name:      "only empty allowed values",
			configure: func(c *oas.JWT) { c.CustomClaimValidation = blockingClaimRule("", nil) },
		},
		{
			name: "base policy claims",
			configure: func(c *oas.JWT) {
				c.CustomClaimValidation = restricting
				c.BasePolicyClaims = []string{"pol"}
			},
		},
		{
			name: "policy field name",
			configure: func(c *oas.JWT) {
				c.CustomClaimValidation = restricting
				c.PolicyFieldName = "pol"
			},
		},
		{
			name: "client base field",
			configure: func(c *oas.JWT) {
				c.CustomClaimValidation = restricting
				c.ClientBaseField = "azp"
			},
		},
		{
			name: "default policies",
			configure: func(c *oas.JWT) {
				c.CustomClaimValidation = restricting
				c.DefaultPolicies = []string{"pol"}
			},
		},
		{
			name: "scope-to-policy mapping in the API definition",
			configure: func(c *oas.JWT) {
				c.CustomClaimValidation = restricting
				c.Scopes = &oas.Scopes{
					ClaimName:            "scope",
					ScopeToPolicyMapping: []oas.ScopeToPolicy{{Scope: "read", PolicyID: "pol"}},
				}
			},
		},
		{
			name: "scope claim name without a mapping",
			configure: func(c *oas.JWT) {
				c.CustomClaimValidation = restricting
				c.Scopes = &oas.Scopes{ClaimName: "scope"}
			},
		},
		{
			name: "scope claims without a mapping",
			configure: func(c *oas.JWT) {
				c.CustomClaimValidation = restricting
				c.Scopes = &oas.Scopes{Claims: []string{"scp"}}
			},
		},
		{
			name:      "scope-to-policy mapping from a registry binding",
			configure: func(c *oas.JWT) { c.CustomClaimValidation = restricting },
			scopeMap:  map[string]string{"read": "pol"},
		},
		{
			name:    "classic API",
			classic: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := buildJWTTestAPI("api", !tc.classic, tc.configure)
			mw := &JWTMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}

			scopeMap := tc.scopeMap
			if scopeMap == nil {
				scopeMap = scopeToPolicyMapForRequest(spec.GetScopeToPolicyMapping(), nil)
			}

			assert.Equal(t, tc.expected, mw.claimsOnlyMode(scopeMap))
		})
	}

	t.Run("classic API ignores a left-over OAS document", func(t *testing.T) {
		spec := claimsOnlyAPI("api")
		spec.IsOAS = false
		mw := &JWTMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}

		assert.False(t, mw.claimsOnlyMode(nil))
	})
}

// A scope claim is a policy field: with it configured the API stays
// policy-based even without a scope-to-policy mapping.
func TestJWTClaimsOnly_ScopeClaimWithoutMappingStaysForbidden(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	alice := "alice-" + uuid.New()

	specs := []*APISpec{
		buildJWTTestAPI("scope-claim-name", true, func(jwtConf *oas.JWT) {
			jwtConf.CustomClaimValidation = blockingClaimRule("trusted-client")
			jwtConf.Scopes = &oas.Scopes{ClaimName: "scope"}
		}),
		buildJWTTestAPI("scope-claims", true, func(jwtConf *oas.JWT) {
			jwtConf.CustomClaimValidation = blockingClaimRule("trusted-client")
			jwtConf.Scopes = &oas.Scopes{Claims: []string{"scp"}}
		}),
	}
	ts.Gw.LoadAPI(specs...)

	headers := jwtWithClaims(map[string]interface{}{
		"user_id":   alice,
		"client_id": "trusted-client",
		"scope":     "read",
		"scp":       "read",
	})

	for _, spec := range specs {
		t.Run(spec.APIID, func(t *testing.T) {
			_, _ = ts.Run(t, test.TestCase{Path: spec.Proxy.ListenPath, Headers: headers, Code: http.StatusForbidden})
		})
	}
}

func TestJWTClaimsOnly_AllowsMatchingClaims(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	alice := "alice-" + uuid.New()

	ts.Gw.LoadAPI(claimsOnlyAPI("claims-api"))

	headers := jwtWithClaims(map[string]interface{}{"user_id": alice, "client_id": "trusted-client"})

	// The existing-session path must accept the session the first request created.
	for i := 0; i < 3; i++ {
		_, _ = ts.Run(t, test.TestCase{Path: "/claims-api/", Headers: headers, Code: http.StatusOK})
	}

	// No policy means no rate limit or quota.
	session, found := ts.storedSession(ts.claimsOnlySessionID("claims-api", alice))
	require.True(t, found)
	assert.Empty(t, session.PolicyIDs())
	assert.Zero(t, session.Rate)
	assert.LessOrEqual(t, session.QuotaMax, int64(0))
}

func TestJWTClaimsOnly_RejectsFailingClaims(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	alice := "alice-" + uuid.New()

	ts.Gw.LoadAPI(claimsOnlyAPI("claims-api"))

	allowed := jwtWithClaims(map[string]interface{}{"user_id": alice, "client_id": "trusted-client"})
	wrongValue := jwtWithClaims(map[string]interface{}{"user_id": alice, "client_id": "other-client"})
	missing := jwtWithClaims(map[string]interface{}{"user_id": alice})

	_, _ = ts.Run(t, []test.TestCase{
		{Path: "/claims-api/", Headers: wrongValue, Code: http.StatusUnauthorized},
		{Path: "/claims-api/", Headers: missing, Code: http.StatusUnauthorized},
		{Path: "/claims-api/", Headers: allowed, Code: http.StatusOK},
		// An existing session does not exempt the identity from the claim rules.
		{Path: "/claims-api/", Headers: wrongValue, Code: http.StatusUnauthorized},
	}...)
}

func TestJWTClaimsOnly_NoRestrictingRuleStaysForbidden(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	alice := "alice-" + uuid.New()

	rules := map[string]map[string]oas.CustomClaimValidationConfig{
		"none": nil,
		"nonblocking": {
			"client_id": {Type: oas.ClaimValidationTypeExactMatch, AllowedValues: []interface{}{"trusted-client"}, NonBlocking: true},
		},
		"required": {
			"client_id": {Type: oas.ClaimValidationTypeRequired},
		},
		"emptyvalue": {
			"client_id": {Type: oas.ClaimValidationTypeContains, AllowedValues: []interface{}{""}},
		},
	}

	specs := []*APISpec{buildJWTTestAPI("classic", false, nil)}
	for name, rule := range rules {
		specs = append(specs, buildJWTTestAPI(name, true, func(jwtConf *oas.JWT) {
			jwtConf.CustomClaimValidation = rule
		}))
	}
	ts.Gw.LoadAPI(specs...)

	headers := jwtWithClaims(map[string]interface{}{"user_id": alice, "client_id": "trusted-client"})

	for _, spec := range specs {
		t.Run(spec.APIID, func(t *testing.T) {
			_, _ = ts.Run(t, []test.TestCase{
				{Path: spec.Proxy.ListenPath, Headers: headers, Code: http.StatusForbidden},
				{Path: spec.Proxy.ListenPath, Headers: headers, Code: http.StatusForbidden},
			}...)

			_, found := ts.storedSession(ts.claimsOnlySessionID(spec.APIID, alice))
			assert.False(t, found)
		})
	}
}

// The same identity alternates between a claims-only and a policy-based API:
// neither session may replace or widen the other.
func TestJWTClaimsOnly_SessionIsolatedFromPolicyBasedAPIs(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	alice := "alice-" + uuid.New()

	policyID := ts.CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			"policy-api": {APIID: "policy-api", Versions: []string{"v1"}},
		}
	})

	policyAPI := buildJWTTestAPI("policy-api", true, func(jwtConf *oas.JWT) {
		jwtConf.PolicyFieldName = "pol"
	})
	restrictedAPI := buildJWTTestAPI("restricted-api", true, func(jwtConf *oas.JWT) {
		jwtConf.PolicyFieldName = "pol"
	})
	ts.Gw.LoadAPI(claimsOnlyAPI("claims-api"), claimsOnlyAPI("claims-api-2"), policyAPI, restrictedAPI)

	claims := map[string]interface{}{"user_id": alice, "client_id": "trusted-client"}
	withoutPolicy := jwtWithClaims(claims)
	claims["pol"] = policyID
	withPolicy := jwtWithClaims(claims)

	for i := 0; i < 2; i++ {
		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/claims-api/", Headers: withPolicy, Code: http.StatusOK},
			{Path: "/policy-api/", Headers: withPolicy, Code: http.StatusOK},
			{Path: "/claims-api-2/", Headers: withoutPolicy, Code: http.StatusOK},
			// The policy does not grant restricted-api, and a claims-only session must not either.
			{Path: "/restricted-api/", Headers: withPolicy, Code: http.StatusForbidden},
			{Path: "/policy-api/", Headers: withoutPolicy, Code: http.StatusForbidden},
		}...)
	}

	shared, found := ts.storedSession(ts.sharedJWTSessionID(alice))
	require.True(t, found)
	assert.Equal(t, []string{policyID}, shared.PolicyIDs())
	assert.Len(t, shared.AccessRights, 1)
	assert.Contains(t, shared.AccessRights, "policy-api")

	for _, apiID := range []string{"claims-api", "claims-api-2"} {
		session, found := ts.storedSession(ts.claimsOnlySessionID(apiID, alice))
		require.True(t, found, apiID)
		assert.Empty(t, session.PolicyIDs())
		assert.Len(t, session.AccessRights, 1)
		assert.Equal(t, apiID, session.AccessRights[apiID].APIID)
	}
}

// The session keys are derivable from the org and the identity, and the Gateway
// accepts a session key as an auth token.
func TestJWTClaimsOnly_DerivedSessionKeyOpensNoOtherAPI(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	alice := "alice-" + uuid.New()

	tokenAPI := BuildAPI(func(spec *APISpec) {
		spec.APIID = "token-api"
		spec.OrgID = claimsOnlyTestOrg
		spec.Proxy.ListenPath = "/token-api/"
		spec.UseKeylessAccess = false
		spec.UseStandardAuth = true
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.AuthTokenType: {AuthHeaderName: "Authorization"},
		}
	})[0]
	ts.Gw.LoadAPI(claimsOnlyAPI("claims-api"), tokenAPI)

	headers := jwtWithClaims(map[string]interface{}{"user_id": alice, "client_id": "trusted-client"})
	_, _ = ts.Run(t, test.TestCase{Path: "/claims-api/", Headers: headers, Code: http.StatusOK})

	_, found := ts.storedSession(ts.sharedJWTSessionID(alice))
	assert.False(t, found, "a claims-only API must not write the session shared by the org's JWT APIs")

	perAPIKey := ts.claimsOnlySessionID("claims-api", alice)
	session, found := ts.storedSession(perAPIKey)
	require.True(t, found)
	require.Len(t, session.AccessRights, 1)
	assert.Contains(t, session.AccessRights, "claims-api")

	for _, key := range []string{perAPIKey, ts.sharedJWTSessionID(alice)} {
		_, _ = ts.Run(t, test.TestCase{
			Path:    "/token-api/",
			Headers: map[string]string{"Authorization": key},
			Code:    http.StatusForbidden,
		})
	}
}

// Scope-to-policy mapping next to claim rules keeps today's behaviour: the
// mapped policy is required and its limits apply, claims still decide first.
func TestJWTClaimsOnly_ScopeMappedConsumptionPolicy(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	alice := "alice-" + uuid.New()
	bob := "bob-" + uuid.New()
	carol := "carol-" + uuid.New()
	dave := "dave-" + uuid.New()

	policyID := ts.CreatePolicy(func(p *user.Policy) {
		p.QuotaMax = 2
		p.QuotaRenewalRate = 3600
		p.AccessRights = map[string]user.AccessDefinition{
			"scoped-api": {APIID: "scoped-api", Versions: []string{"v1"}},
		}
	})

	ts.Gw.LoadAPI(buildJWTTestAPI("scoped-api", true, func(jwtConf *oas.JWT) {
		jwtConf.CustomClaimValidation = blockingClaimRule("trusted-client")
		jwtConf.Scopes = &oas.Scopes{
			ClaimName:            "scope",
			ScopeToPolicyMapping: []oas.ScopeToPolicy{{Scope: "consume", PolicyID: policyID}},
		}
	}))

	withScope := jwtWithClaims(map[string]interface{}{"user_id": alice, "client_id": "trusted-client", "scope": "consume"})
	noScope := jwtWithClaims(map[string]interface{}{"user_id": bob, "client_id": "trusted-client"})
	unmappedScope := jwtWithClaims(map[string]interface{}{"user_id": carol, "client_id": "trusted-client", "scope": "other"})
	wrongClaim := jwtWithClaims(map[string]interface{}{"user_id": dave, "client_id": "other-client", "scope": "consume"})

	_, _ = ts.Run(t, []test.TestCase{
		{Path: "/scoped-api/", Headers: wrongClaim, Code: http.StatusUnauthorized},
		{Path: "/scoped-api/", Headers: noScope, Code: http.StatusForbidden},
		{Path: "/scoped-api/", Headers: unmappedScope, Code: http.StatusForbidden},
		{Path: "/scoped-api/", Headers: withScope, Code: http.StatusOK},
		{Path: "/scoped-api/", Headers: withScope, Code: http.StatusOK},
		{Path: "/scoped-api/", Headers: withScope, Code: http.StatusForbidden, BodyMatch: "Quota exceeded"},
	}...)

	session, found := ts.storedSession(ts.sharedJWTSessionID(alice))
	require.True(t, found)
	assert.Equal(t, []string{policyID}, session.PolicyIDs())
}

func TestJWTClaimsOnly_RestrictSessionToAPI(t *testing.T) {
	spec := claimsOnlyAPI("claims-api")
	mw := &JWTMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}

	t.Run("empty access rights", func(t *testing.T) {
		session := user.SessionState{}

		assert.True(t, mw.restrictSessionToAPI(&session))
		assert.Len(t, session.AccessRights, 1)
		assert.Equal(t, "claims-api", session.AccessRights["claims-api"].APIID)
		assert.False(t, mw.restrictSessionToAPI(&session))
	})

	t.Run("access rights granting other APIs", func(t *testing.T) {
		limit := user.APILimit{QuotaMax: 5}
		session := user.SessionState{AccessRights: map[string]user.AccessDefinition{
			"claims-api": {APIID: "claims-api", Limit: limit},
			"other-api":  {APIID: "other-api"},
		}}

		assert.True(t, mw.restrictSessionToAPI(&session))
		assert.Len(t, session.AccessRights, 1)
		assert.Equal(t, limit, session.AccessRights["claims-api"].Limit)
	})

	t.Run("access rights granting only other APIs", func(t *testing.T) {
		session := user.SessionState{AccessRights: map[string]user.AccessDefinition{
			"other-api": {APIID: "other-api"},
		}}

		assert.True(t, mw.restrictSessionToAPI(&session))
		assert.Len(t, session.AccessRights, 1)
		assert.Contains(t, session.AccessRights, "claims-api")
	})
}

func TestJWTClaimsOnly_SessionKeyID(t *testing.T) {
	keyID := claimsOnlySessionKeyID("api-1", "alice")

	assert.Equal(t, keyID, claimsOnlySessionKeyID("api-1", "alice"))
	assert.NotEqual(t, keyID, claimsOnlySessionKeyID("api-2", "alice"))
	assert.NotEqual(t, keyID, claimsOnlySessionKeyID("api-1", "bob"))
	assert.NotEqual(t, claimsOnlySessionKeyID("a", "bc"), claimsOnlySessionKeyID("ab", "c"))
	assert.NotEqual(t, len(fmt.Sprintf("%x", md5.Sum([]byte("alice")))), len(keyID))
}

func TestCustomClaimsContainsMatch(t *testing.T) {
	cases := []struct {
		name     string
		allowed  []interface{}
		claim    interface{}
		expected bool
	}{
		{"number matches first value", []interface{}{float64(1), float64(2)}, float64(1), true},
		{"number matches last value", []interface{}{float64(1), float64(2)}, float64(2), true},
		{"number matches no value", []interface{}{float64(1), float64(2)}, float64(3), false},
		{"boolean matches first value", []interface{}{true, false}, true, true},
		{"boolean matches no value", []interface{}{false}, true, false},
		{"string contains first value", []interface{}{"admin", "write"}, "admin:users", true},
		{"string contains no value", []interface{}{"admin", "write"}, "read:users", false},
		{"array contains first value", []interface{}{"a", "b"}, []interface{}{"a", "z"}, true},
		{"array contains no value", []interface{}{"a", "b"}, []interface{}{"y", "z"}, false},
		{"no allowed values", nil, "anything", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, customClaimsContainsMatch(tc.allowed, tc.claim))
		})
	}
}

// A numeric claim must match any allowed value end to end, not just the last one.
func TestJWTClaimsOnly_NumericContainsRule(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	alice := "alice-" + uuid.New()
	bob := "bob-" + uuid.New()
	carol := "carol-" + uuid.New()

	ts.Gw.LoadAPI(buildJWTTestAPI("tier-api", true, func(jwtConf *oas.JWT) {
		jwtConf.CustomClaimValidation = map[string]oas.CustomClaimValidationConfig{
			"tier": {Type: oas.ClaimValidationTypeContains, AllowedValues: []interface{}{1, 2}},
		}
	}))

	_, _ = ts.Run(t, []test.TestCase{
		{Path: "/tier-api/", Headers: jwtWithClaims(map[string]interface{}{"user_id": alice, "tier": 1}), Code: http.StatusOK},
		{Path: "/tier-api/", Headers: jwtWithClaims(map[string]interface{}{"user_id": bob, "tier": 2}), Code: http.StatusOK},
		{Path: "/tier-api/", Headers: jwtWithClaims(map[string]interface{}{"user_id": carol, "tier": 3}), Code: http.StatusUnauthorized},
	}...)
}

// On a multi-auth API in compliant mode the claim rules are the only access
// control, so the derivable claims-only session key must not pass as an auth token.
func TestJWTClaimsOnly_SessionKeyRejectedByOtherAuthMethods(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	alice := "alice-" + uuid.New()

	spec := claimsOnlyAPI("multi-auth-api")
	spec.OAS.Components.SecuritySchemes["apiKey"] = &openapi3.SecuritySchemeRef{
		Value: &openapi3.SecurityScheme{Type: "apiKey", In: "header", Name: "X-Tyk-Key"},
	}
	spec.OAS.Security = openapi3.SecurityRequirements{{"jwtAuth": []string{}}, {"apiKey": []string{}}}
	authentication := spec.OAS.GetTykExtension().Server.Authentication
	authentication.SecurityProcessingMode = oas.SecurityProcessingModeCompliant
	enabled := true
	authentication.SecuritySchemes["apiKey"] = &oas.Token{
		Enabled:     &enabled,
		AuthSources: oas.AuthSources{Header: &oas.AuthSource{Enabled: true, Name: "X-Tyk-Key"}},
	}
	spec.OAS.ExtractTo(spec.APIDefinition)
	ts.Gw.LoadAPI(spec)

	headers := jwtWithClaims(map[string]interface{}{"user_id": alice, "client_id": "trusted-client"})
	perAPIKey := ts.claimsOnlySessionID("multi-auth-api", alice)

	_, _ = ts.Run(t, test.TestCase{Path: "/multi-auth-api/", Headers: headers, Code: http.StatusOK})
	_, found := ts.storedSession(perAPIKey)
	require.True(t, found)

	_, _ = ts.Run(t, []test.TestCase{
		{Path: "/multi-auth-api/", Headers: map[string]string{"X-Tyk-Key": perAPIKey}, Code: http.StatusForbidden},
		{Path: "/multi-auth-api/", Headers: headers, Code: http.StatusOK},
	}...)
}

// A claims-only session is a cache of the JWT: its Redis record expires with
// the token, and without an exp claim after a bounded lifetime.
func TestJWTClaimsOnly_SessionLifetimeIsBounded(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.LoadAPI(claimsOnlyAPI("claims-api"))
	store := ts.Gw.GlobalSessionManager.Store()

	t.Run("expires with the JWT", func(t *testing.T) {
		alice := "alice-" + uuid.New()
		exp := time.Now().Add(10 * time.Minute).Unix()

		headers := jwtWithClaims(map[string]interface{}{"user_id": alice, "client_id": "trusted-client", "exp": exp})
		_, _ = ts.Run(t, test.TestCase{Path: "/claims-api/", Headers: headers, Code: http.StatusOK})

		sessionID := ts.claimsOnlySessionID("claims-api", alice)
		session, found := ts.storedSession(sessionID)
		require.True(t, found)
		assert.Equal(t, exp, session.Expires)

		ttl, err := store.GetExp(sessionID)
		require.NoError(t, err)
		assert.Greater(t, ttl, int64(0))
		assert.LessOrEqual(t, ttl, exp-time.Now().Unix()+1)
	})

	t.Run("bounded without exp", func(t *testing.T) {
		bob := "bob-" + uuid.New()

		headers := jwtWithClaims(map[string]interface{}{"user_id": bob, "client_id": "trusted-client", "exp": nil})
		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/claims-api/", Headers: headers, Code: http.StatusOK},
			{Path: "/claims-api/", Headers: headers, Code: http.StatusOK},
		}...)

		sessionID := ts.claimsOnlySessionID("claims-api", bob)
		session, found := ts.storedSession(sessionID)
		require.True(t, found)
		assert.Zero(t, session.Expires, "a JWT without exp does not expire")

		ttl, err := store.GetExp(sessionID)
		require.NoError(t, err)
		assert.Greater(t, ttl, int64(0))
		assert.LessOrEqual(t, ttl, claimsOnlySessionLifetime)
	})
}
