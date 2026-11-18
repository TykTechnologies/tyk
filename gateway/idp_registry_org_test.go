package gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/cache"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

const (
	idpOrgOne = "org-one"
	idpOrgTwo = "org-two"
)

// idpTestIssuer is a locally controlled IdP: an RSA key behind its own JWKS
// endpoint.
type idpTestIssuer struct {
	issuer  string
	kid     string
	jwksURI string
	key     *rsa.PrivateKey
}

func newIDPTestIssuer(t *testing.T, issuer, kid string) *idpTestIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	body, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &key.PublicKey, KeyID: kid, Algorithm: "RS512", Use: "sig"},
	}})
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mustWriteJSON(t, w, string(body))
	}))
	t.Cleanup(srv.Close)

	return &idpTestIssuer{issuer: issuer, kid: kid, jwksURI: srv.URL, key: key}
}

// token signs a token with this IdP's key, kid and issuer; mutate may change or
// delete any of them.
func (i *idpTestIssuer) token(t *testing.T, mutate ...func(*jwt.Token)) string {
	t.Helper()
	tok := jwt.New(jwt.GetSigningMethod("RS512"))
	tok.Header[KID] = i.kid
	claims := tok.Claims.(jwt.MapClaims) //nolint:errcheck
	claims[ISS] = i.issuer
	claims["user_id"] = "user"
	claims["scope"] = "read"
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	for _, m := range mutate {
		m(tok)
	}
	signed, err := tok.SignedString(i.key)
	require.NoError(t, err)
	return signed
}

func (i *idpTestIssuer) idp(id, orgID string, mappings map[string]ScopeMapping) IdP {
	return IdP{ID: id, OrgID: orgID, Issuer: i.issuer, JWKSURI: i.jwksURI, APIMappings: mappings}
}

func withoutIss(tok *jwt.Token) {
	delete(tok.Claims.(jwt.MapClaims), ISS) //nolint:errcheck
}

func withIss(iss interface{}) func(*jwt.Token) {
	return func(tok *jwt.Token) {
		tok.Claims.(jwt.MapClaims)[ISS] = iss //nolint:errcheck
	}
}

func TestIdPRegistry_Rebuild_OrgOwnership(t *testing.T) {
	gw := &Gateway{apisByID: map[string]*APISpec{
		"api-org-two": specInOrg(idpOrgTwo),
		"api-org-one": specInOrg(idpOrgOne),
		"api-no-org":  specInOrg(""),
		"api-no-def":  {},
	}}
	r := newIdPRegistry(gw)

	scopes := ScopeMapping{ScopeToPolicy: map[string]string{"read": "pol"}}

	r.rebuild([]IdP{
		{
			ID: "mixed", OrgID: idpOrgOne, Issuer: "https://issuer-one.example",
			APIMappings: map[string]ScopeMapping{
				"api-org-one":  scopes,
				"api-org-two":  scopes,
				"api-no-org":   scopes,
				"api-no-def":   scopes,
				"api-unloaded": scopes,
			},
		},
		{
			ID: "foreign-only", OrgID: idpOrgOne, Issuer: "https://issuer-one-b.example",
			APIMappings: map[string]ScopeMapping{"api-org-two": scopes},
		},
		{
			ID: "no-org", OrgID: "", Issuer: "https://no-org",
			APIMappings: map[string]ScopeMapping{"api-no-org": scopes, "api-org-two": scopes},
		},
		{
			ID: "no-issuer", OrgID: idpOrgTwo, Issuer: "",
			APIMappings: map[string]ScopeMapping{"api-org-two": scopes},
		},
	})

	own := r.BindingsForAPI("api-org-one")
	require.Len(t, own, 1, "the valid mapping of a mixed record is kept")
	assert.Equal(t, Binding{
		OrgID:         idpOrgOne,
		IdPID:         "mixed",
		Issuer:        "https://issuer-one.example",
		ScopeToPolicy: scopes.ScopeToPolicy,
	}, own[0])

	for _, apiID := range []string{"api-org-two", "api-no-org", "api-no-def", "api-unloaded"} {
		assert.Empty(t, r.BindingsForAPI(apiID), apiID)
	}

	_, ok := r.IdP(idpOrgOne, "mixed")
	assert.True(t, ok)
	for _, id := range []string{"foreign-only", "no-org", "no-issuer"} {
		for _, org := range []string{idpOrgOne, idpOrgTwo, ""} {
			_, ok := r.IdP(org, id)
			assert.False(t, ok, "%s must not be stored (lookup org %q)", id, org)
		}
	}
	_, ok = r.IdP(idpOrgTwo, "mixed")
	assert.False(t, ok, "an IdP is not visible through another Organisation")
}

// Two Organisations may use the same client_idp_id. Whatever the feed order,
// and across refreshes, each API binds its own Organisation's record.
func TestIdPRegistry_Rebuild_DuplicateIDAcrossOrgs(t *testing.T) {
	gw := &Gateway{apisByID: map[string]*APISpec{
		"api-org-two": specInOrg(idpOrgTwo),
		"api-org-one": specInOrg(idpOrgOne),
	}}
	r := newIdPRegistry(gw)

	two := IdP{
		ID: "shared-idp", OrgID: idpOrgTwo, Issuer: "https://issuer-two.example", JWKSURI: "https://org-two/jwks",
		APIMappings: map[string]ScopeMapping{"api-org-two": {ScopeToPolicy: map[string]string{"read": "pol-two"}}},
	}
	one := IdP{
		ID: "shared-idp", OrgID: idpOrgOne, Issuer: "https://issuer-one.example", JWKSURI: "https://org-one/jwks",
		APIMappings: map[string]ScopeMapping{"api-org-one": {}},
	}

	check := func(t *testing.T) {
		t.Helper()
		b := r.BindingsForAPI("api-org-two")
		require.Len(t, b, 1)
		assert.Equal(t, Binding{
			OrgID:         idpOrgTwo,
			IdPID:         "shared-idp",
			Issuer:        "https://issuer-two.example",
			JWKSURI:       "https://org-two/jwks",
			ScopeToPolicy: map[string]string{"read": "pol-two"},
		}, b[0])

		b = r.BindingsForAPI("api-org-one")
		require.Len(t, b, 1)
		assert.Equal(t, Binding{
			OrgID:   idpOrgOne,
			IdPID:   "shared-idp",
			Issuer:  "https://issuer-one.example",
			JWKSURI: "https://org-one/jwks",
		}, b[0])

		got, ok := r.IdP(idpOrgTwo, "shared-idp")
		require.True(t, ok)
		assert.Equal(t, "https://org-two/jwks", got.JWKSURI)
		got, ok = r.IdP(idpOrgOne, "shared-idp")
		require.True(t, ok)
		assert.Equal(t, "https://org-one/jwks", got.JWKSURI)
	}

	feeds := map[string][]IdP{
		"org two first": {two, one},
		"org one first": {one, two},
	}
	for name, feed := range feeds {
		t.Run(name, func(t *testing.T) {
			r.rebuild(feed)
			check(t)
		})
	}

	t.Run("refresh in the other order", func(t *testing.T) {
		r.rebuild(feeds["org two first"])
		r.rebuild(feeds["org one first"])
		check(t)
		r.rebuild(feeds["org two first"])
		check(t)
	})

	t.Run("org one record removed", func(t *testing.T) {
		r.rebuild([]IdP{two})
		assert.Empty(t, r.BindingsForAPI("api-org-one"))
		_, ok := r.IdP(idpOrgOne, "shared-idp")
		assert.False(t, ok)
		require.Len(t, r.BindingsForAPI("api-org-two"), 1)
	})
}

// idpIsolationEnv is a gateway loading APIs of two Organisations, each with its
// own IdP. Rejections are pinned to 403, the status of a failed key resolution
// or signature check; the upstream answers 200.
type idpIsolationEnv struct {
	ts        *Test
	one, two  *idpTestIssuer
	policyTwo string
	policyOne string
}

const (
	idpAPIOrgTwo        = "api-org-two"
	idpAPIOrgTwoDefault = "api-org-two-default"
	idpAPIOrgOne        = "api-org-one"
)

func newIDPIsolationEnv(t *testing.T, conf ...func(*config.Config)) *idpIsolationEnv {
	t.Helper()
	ts := StartTest(func(c *config.Config) {
		for _, fn := range conf {
			fn(c)
		}
	})
	t.Cleanup(ts.Close)

	env := &idpIsolationEnv{
		ts:  ts,
		one: newIDPTestIssuer(t, "https://issuer-one.example", "kid-one"),
		two: newIDPTestIssuer(t, "https://issuer-two.example", "kid-two"),
	}

	env.policyTwo = ts.CreatePolicy(func(p *user.Policy) {
		p.OrgID = idpOrgTwo
		p.AccessRights = map[string]user.AccessDefinition{
			idpAPIOrgTwo:        {APIID: idpAPIOrgTwo},
			idpAPIOrgTwoDefault: {APIID: idpAPIOrgTwoDefault},
		}
		p.Partitions = user.PolicyPartitions{Acl: true}
	})
	env.policyOne = ts.CreatePolicy(func(p *user.Policy) {
		p.OrgID = idpOrgOne
		p.AccessRights = map[string]user.AccessDefinition{idpAPIOrgOne: {APIID: idpAPIOrgOne}}
		p.Partitions = user.PolicyPartitions{Acl: true}
	})

	registryAPI := func(apiID, orgID, listenPath string) func(*APISpec) {
		return func(spec *APISpec) {
			spec.APIID = apiID
			spec.OrgID = orgID
			spec.UseKeylessAccess = false
			spec.EnableJWT = true
			spec.JWTSigningMethod = RSASign
			spec.JWTIdentityBaseField = "user_id"
			spec.Proxy.ListenPath = listenPath
		}
	}
	ts.Gw.BuildAndLoadAPI(
		registryAPI(idpAPIOrgTwo, idpOrgTwo, "/org-two/"),
		func(spec *APISpec) {
			registryAPI(idpAPIOrgTwoDefault, idpOrgTwo, "/org-two-default/")(spec)
			spec.JWTDefaultPolicies = []string{env.policyTwo}
		},
		registryAPI(idpAPIOrgOne, idpOrgOne, "/org-one/"),
	)
	return env
}

func (e *idpIsolationEnv) orgTwoIdP(id string) IdP {
	return e.two.idp(id, idpOrgTwo, map[string]ScopeMapping{
		idpAPIOrgTwo:        {ScopeToPolicy: map[string]string{"read": e.policyTwo}},
		idpAPIOrgTwoDefault: {},
	})
}

func (e *idpIsolationEnv) expect(t *testing.T, path, token string, code int) {
	t.Helper()
	_, _ = e.ts.Run(t, test.TestCase{
		Path:    path,
		Headers: map[string]string{"authorization": token},
		Code:    code,
	})
}

// An IdP mapping another Organisation's API, as persisted before the Dashboard
// validated ownership, authenticates nobody there.
func TestIdPRegistry_JWT_ForeignOrgMappingDenied(t *testing.T) {
	env := newIDPIsolationEnv(t)

	foreign := env.one.idp("idp-one", idpOrgOne, map[string]ScopeMapping{
		idpAPIOrgTwo:        {ScopeToPolicy: map[string]string{"read": env.policyTwo}},
		idpAPIOrgTwoDefault: {},
		idpAPIOrgOne:        {ScopeToPolicy: map[string]string{"read": env.policyOne}},
	})
	// Same key and mappings, but no owner at all.
	ownerless := foreign
	ownerless.ID, ownerless.OrgID = "idp-ownerless", ""

	feeds := map[string][]IdP{
		"org two first": {env.orgTwoIdP("idp-two"), foreign, ownerless},
		"org one first": {ownerless, foreign, env.orgTwoIdP("idp-two")},
	}
	for name, feed := range feeds {
		t.Run(name, func(t *testing.T) {
			env.ts.Gw.idpRegistry.rebuild(feed)

			// Org two authenticates first, so org one's tokens for the same
			// subject meet an existing session.
			env.expect(t, "/org-two/", env.two.token(t), http.StatusOK)
			env.expect(t, "/org-two/", env.one.token(t), http.StatusForbidden)
			env.expect(t, "/org-two/", env.one.token(t, withoutIss), http.StatusForbidden)
			env.expect(t, "/org-two/", env.one.token(t, withIss(env.two.issuer)), http.StatusForbidden)

			// The default Policy grants access without any scope mapping.
			env.expect(t, "/org-two-default/", env.two.token(t), http.StatusOK)
			env.expect(t, "/org-two-default/", env.one.token(t), http.StatusForbidden)
			env.expect(t, "/org-two-default/", env.one.token(t, withoutIss), http.StatusForbidden)

			env.expect(t, "/org-one/", env.one.token(t), http.StatusOK)
			env.expect(t, "/org-one/", env.two.token(t), http.StatusForbidden)
		})
	}
}

// With one client_idp_id in both Organisations and no foreign mapping, neither
// record replaces the other's key, issuer or scope mapping.
func TestIdPRegistry_JWT_DuplicateIDAcrossOrgs(t *testing.T) {
	env := newIDPIsolationEnv(t)

	two := env.orgTwoIdP("shared-idp")
	one := env.one.idp("shared-idp", idpOrgOne, map[string]ScopeMapping{
		idpAPIOrgOne: {ScopeToPolicy: map[string]string{"read": env.policyOne}},
	})

	check := func(t *testing.T) {
		t.Helper()
		env.expect(t, "/org-two/", env.two.token(t), http.StatusOK)
		env.expect(t, "/org-two/", env.one.token(t), http.StatusForbidden)
		env.expect(t, "/org-two/", env.one.token(t, withoutIss), http.StatusForbidden)
		env.expect(t, "/org-two-default/", env.one.token(t), http.StatusForbidden)
		env.expect(t, "/org-one/", env.one.token(t), http.StatusOK)
		env.expect(t, "/org-one/", env.two.token(t), http.StatusForbidden)
	}

	registry := env.ts.Gw.idpRegistry
	t.Run("org two first", func(t *testing.T) {
		registry.rebuild([]IdP{two, one})
		check(t)
	})
	t.Run("org one first", func(t *testing.T) {
		registry.rebuild([]IdP{one, two})
		check(t)
	})
	t.Run("refreshed in the other order", func(t *testing.T) {
		registry.rebuild([]IdP{two, one})
		check(t)
	})
	t.Run("org one record deleted and recreated", func(t *testing.T) {
		registry.rebuild([]IdP{two})
		env.expect(t, "/org-two/", env.two.token(t), http.StatusOK)
		env.expect(t, "/org-one/", env.one.token(t), http.StatusForbidden)
		registry.rebuild([]IdP{one, two})
		check(t)
	})
}

// The registry path needs a string iss equal to the IdP's issuer, with no OAS
// allowed-issuer list configured.
func TestIdPRegistry_JWT_IssuerValidation(t *testing.T) {
	env := newIDPIsolationEnv(t)
	two := env.two
	env.ts.Gw.idpRegistry.rebuild([]IdP{env.orgTwoIdP("idp-two")})

	env.expect(t, "/org-two/", two.token(t), http.StatusOK)

	rejected := map[string]func(*jwt.Token){
		"absent":     withoutIss,
		"empty":      withIss(""),
		"null":       withIss(nil),
		"number":     withIss(42),
		"array":      withIss([]string{two.issuer}),
		"mismatched": withIss("https://other.example"),
		"prefix":     withIss(two.issuer + "/"),
	}
	for name, mutate := range rejected {
		t.Run(name, func(t *testing.T) {
			env.expect(t, "/org-two/", two.token(t, mutate), http.StatusForbidden)
			env.expect(t, "/org-two-default/", two.token(t, mutate), http.StatusForbidden)
		})
	}

	t.Run("matching issuer signed with another key", func(t *testing.T) {
		otherKey := env.one.token(t, withIss(two.issuer), func(tok *jwt.Token) {
			tok.Header[KID] = two.kid
		})
		env.expect(t, "/org-two/", otherKey, http.StatusForbidden)
		env.expect(t, "/org-two-default/", otherKey, http.StatusForbidden)
	})

	env.expect(t, "/org-two/", two.token(t), http.StatusOK)
}

// A persisted IdP without an issuer is never a trust source, and does not
// become one for tokens that name no issuer.
func TestIdPRegistry_JWT_EmptyIssuerIdPIgnored(t *testing.T) {
	env := newIDPIsolationEnv(t)

	noIssuer := env.orgTwoIdP("idp-two")
	noIssuer.Issuer = ""
	env.ts.Gw.idpRegistry.rebuild([]IdP{noIssuer})

	for name, mutate := range map[string]func(*jwt.Token){
		"token issuer absent": withoutIss,
		"token issuer empty":  withIss(""),
		"token issuer set":    withIss(env.two.issuer),
	} {
		t.Run(name, func(t *testing.T) {
			env.expect(t, "/org-two/", env.two.token(t, mutate), http.StatusForbidden)
			env.expect(t, "/org-two-default/", env.two.token(t, mutate), http.StatusForbidden)
		})
	}

	env.ts.Gw.idpRegistry.rebuild([]IdP{env.orgTwoIdP("idp-two")})
	env.expect(t, "/org-two/", env.two.token(t), http.StatusOK)
}

// A manual jwt_source stays the only key source: its tokens need no iss, and a
// key known only to a registry IdP bound to the same API is not accepted.
func TestIdPRegistry_JWT_ManualSourcePrecedence(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const apiID = "idp-manual-api"
	registryIdP := newIDPTestIssuer(t, "https://issuer.example", "kid-registry")

	pID := ts.CreatePolicy(func(p *user.Policy) {
		p.OrgID = idpOrgTwo
		p.AccessRights = map[string]user.AccessDefinition{apiID: {APIID: apiID}}
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.OrgID = idpOrgTwo
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = testHttpJWK
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/manual/"
	})
	ts.Gw.idpRegistry.rebuild([]IdP{registryIdP.idp("idp-1", idpOrgTwo, map[string]ScopeMapping{
		apiID: {ScopeToPolicy: map[string]string{"read": pID}},
	})})
	require.Len(t, ts.Gw.idpRegistry.BindingsForAPI(apiID), 1)

	manualToken := CreateJWKToken(func(tok *jwt.Token) {
		tok.Header[KID] = "12345"
		claims := tok.Claims.(jwt.MapClaims) //nolint:errcheck
		claims["user_id"] = "user"
		claims["policy_id"] = pID
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	})
	registryToken := registryIdP.token(t, func(tok *jwt.Token) {
		tok.Claims.(jwt.MapClaims)["policy_id"] = pID //nolint:errcheck
	})

	_, _ = ts.Run(t, []test.TestCase{
		{Path: "/manual/", Headers: map[string]string{"authorization": manualToken}, Code: http.StatusOK},
		{Path: "/manual/", Headers: map[string]string{"authorization": registryToken}, Code: http.StatusForbidden},
	}...)
}

// OAS jwksURIs are consulted instead of the registry, never after it.
func TestIdPRegistry_JWT_OASJwksURIsPrecedence(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const apiID = "idp-oas-api"
	registryIdP := newIDPTestIssuer(t, "https://issuer.example", "kid-registry")

	spec := &APISpec{APIDefinition: &apidef.APIDefinition{
		APIID:            apiID,
		OrgID:            idpOrgTwo,
		IsOAS:            true,
		JWTSigningMethod: RSASign,
		JWTJwksURIs:      []apidef.JWK{{URL: testHttpJWK}},
	}}
	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID[apiID] = spec
	ts.Gw.apisMu.Unlock()
	ts.Gw.idpRegistry.rebuild([]IdP{registryIdP.idp("idp-1", idpOrgTwo, map[string]ScopeMapping{apiID: {}})})
	require.Len(t, ts.Gw.idpRegistry.BindingsForAPI(apiID), 1)

	k := &JWTMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: ts.Gw}}
	k.Gw.SetConfig(config.Config{})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	manual := &jwt.Token{Header: map[string]interface{}{KID: "12345"}, Claims: jwt.MapClaims{}}
	key, err := k.getSecretToVerifySignature(r, manual)
	require.NoError(t, err)
	assert.NotNil(t, key)
	assert.Nil(t, ctxGetMatchedBinding(r))

	registry := &jwt.Token{
		Header: map[string]interface{}{KID: registryIdP.kid},
		Claims: jwt.MapClaims{ISS: registryIdP.issuer},
	}
	key, err = k.getSecretToVerifySignature(r, registry)
	require.Error(t, err)
	assert.Nil(t, key)
	assert.Nil(t, ctxGetMatchedBinding(r))
}

func allowMissingIssuer(c *config.Config) {
	c.AllowUnsafeIDPMissingIssuer = true
}

func gatewayAllowingMissingIssuer(apis map[string]*APISpec) *Gateway {
	gw := &Gateway{apisByID: apis}
	gw.SetConfig(config.Config{AllowUnsafeIDPMissingIssuer: true})
	return gw
}

// allow_unsafe_idp_missing_issuer binds IdPs without an issuer, and nothing
// else that the default drops.
func TestIdPRegistry_Rebuild_AllowMissingIssuer(t *testing.T) {
	gw := gatewayAllowingMissingIssuer(map[string]*APISpec{
		"api-org-one": specInOrg(idpOrgOne),
		"api-org-two": specInOrg(idpOrgTwo),
		"api-no-org":  specInOrg(""),
	})
	r := newIdPRegistry(gw)

	scopes := ScopeMapping{ScopeToPolicy: map[string]string{"read": "pol"}}
	r.rebuild([]IdP{
		{
			ID: "no-issuer", OrgID: idpOrgTwo, JWKSURI: "https://issuer-two.example/jwks",
			APIMappings: map[string]ScopeMapping{"api-org-two": scopes, "api-org-one": scopes, "api-no-org": scopes},
		},
		{
			ID: "no-org", OrgID: "",
			APIMappings: map[string]ScopeMapping{"api-no-org": scopes, "api-org-two": scopes},
		},
		{
			ID: "other-org", OrgID: idpOrgOne,
			APIMappings: map[string]ScopeMapping{"api-org-two": scopes},
		},
	})

	own := r.BindingsForAPI("api-org-two")
	require.Len(t, own, 1)
	assert.Equal(t, Binding{
		OrgID:         idpOrgTwo,
		IdPID:         "no-issuer",
		JWKSURI:       "https://issuer-two.example/jwks",
		ScopeToPolicy: scopes.ScopeToPolicy,
	}, own[0])
	assert.Empty(t, r.BindingsForAPI("api-org-one"))
	assert.Empty(t, r.BindingsForAPI("api-no-org"))

	_, ok := r.IdP(idpOrgTwo, "no-issuer")
	assert.True(t, ok)
	_, ok = r.IdP("", "no-org")
	assert.False(t, ok)
	_, ok = r.IdP(idpOrgOne, "other-org")
	assert.False(t, ok)
}

func TestKeyForBinding_AllowMissingIssuer(t *testing.T) {
	k := newTestJWTMiddleware("api-a")
	set := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: []byte("secret"), KeyID: "kid"}}}
	k.loadOrCreateJWKCache().Set("https://i1/jwks", set, cache.DefaultExpiration)

	withIssuer := Binding{OrgID: "org-1", IdPID: "idp-1", Issuer: "https://real", JWKSURI: "https://i1/jwks"}
	noIssuer, otherOrg, noOrg := withIssuer, withIssuer, withIssuer
	noIssuer.Issuer = ""
	otherOrg.OrgID = "org-2"
	noOrg.OrgID = ""

	cases := []struct {
		name    string
		binding Binding
		iss     string
		matches bool
	}{
		{"matching issuer", withIssuer, "https://real", true},
		{"token without issuer", withIssuer, "", true},
		{"IdP and token without issuer", noIssuer, "", true},
		{"issuer mismatch", withIssuer, "https://other", false},
		{"IdP without issuer, token with one", noIssuer, "https://real", false},
		{"other Organisation", otherOrg, "", false},
		{"other Organisation, matching issuer", otherOrg, "https://real", false},
		{"binding without Organisation", noOrg, "", false},
	}
	for _, tc := range cases {
		got := k.keyForBinding(tc.binding, tc.iss, "kid", true)
		assert.Equal(t, tc.matches, got != nil, tc.name)
	}

	k.Spec.OrgID = ""
	assert.Nil(t, k.keyForBinding(noOrg, "", "kid", true), "empty Organisation on both sides must not match")
}

// With allow_unsafe_idp_missing_issuer an IdP without an issuer is bound, and
// accepts tokens that name no issuer.
func TestIdPRegistry_JWT_AllowMissingIssuer_EmptyIssuerIdP(t *testing.T) {
	env := newIDPIsolationEnv(t, allowMissingIssuer)

	noIssuer := env.orgTwoIdP("idp-two")
	noIssuer.Issuer = ""
	env.ts.Gw.idpRegistry.rebuild([]IdP{noIssuer})

	accepted := map[string]func(*jwt.Token){
		"absent": withoutIss,
		"empty":  withIss(""),
		"null":   withIss(nil),
		"number": withIss(42),
	}
	for name, mutate := range accepted {
		t.Run(name, func(t *testing.T) {
			env.expect(t, "/org-two/", env.two.token(t, mutate), http.StatusOK)
			env.expect(t, "/org-two-default/", env.two.token(t, mutate), http.StatusOK)
		})
	}

	t.Run("token names an issuer", func(t *testing.T) {
		env.expect(t, "/org-two/", env.two.token(t), http.StatusForbidden)
		env.expect(t, "/org-two-default/", env.two.token(t), http.StatusForbidden)
	})

	t.Run("signed with another key", func(t *testing.T) {
		otherKey := env.one.token(t, withoutIss, func(tok *jwt.Token) {
			tok.Header[KID] = env.two.kid
		})
		env.expect(t, "/org-two/", otherKey, http.StatusForbidden)
	})
}

// A token that names an issuer still needs the exact match; one that names none
// is matched by kid.
func TestIdPRegistry_JWT_AllowMissingIssuer_IssuerStillMatched(t *testing.T) {
	env := newIDPIsolationEnv(t, allowMissingIssuer)
	two := env.two
	env.ts.Gw.idpRegistry.rebuild([]IdP{env.orgTwoIdP("idp-two")})

	env.expect(t, "/org-two/", two.token(t), http.StatusOK)
	env.expect(t, "/org-two/", two.token(t, withoutIss), http.StatusOK)
	env.expect(t, "/org-two/", two.token(t, withIss("")), http.StatusOK)

	for name, mutate := range map[string]func(*jwt.Token){
		"mismatched": withIss("https://other.example"),
		"prefix":     withIss(two.issuer + "/"),
	} {
		t.Run(name, func(t *testing.T) {
			env.expect(t, "/org-two/", two.token(t, mutate), http.StatusForbidden)
			env.expect(t, "/org-two-default/", two.token(t, mutate), http.StatusForbidden)
		})
	}

	t.Run("matching issuer signed with another key", func(t *testing.T) {
		otherKey := env.one.token(t, withIss(two.issuer), func(tok *jwt.Token) {
			tok.Header[KID] = two.kid
		})
		env.expect(t, "/org-two/", otherKey, http.StatusForbidden)
	})
}

// allow_unsafe_idp_missing_issuer does not relax Organisation ownership: IdPs
// of another Organisation, or of none, stay unbound whatever their issuer.
func TestIdPRegistry_JWT_AllowMissingIssuer_ForeignOrgMappingDenied(t *testing.T) {
	env := newIDPIsolationEnv(t, allowMissingIssuer)

	mappings := map[string]ScopeMapping{
		idpAPIOrgTwo:        {ScopeToPolicy: map[string]string{"read": env.policyTwo}},
		idpAPIOrgTwoDefault: {},
		idpAPIOrgOne:        {ScopeToPolicy: map[string]string{"read": env.policyOne}},
	}
	foreign := env.one.idp("idp-one", idpOrgOne, mappings)
	foreignNoIssuer := foreign
	foreignNoIssuer.ID, foreignNoIssuer.Issuer = "idp-one-no-issuer", ""
	ownerless := foreignNoIssuer
	ownerless.ID, ownerless.OrgID = "idp-ownerless", ""

	orgTwo := map[string]IdP{
		"with issuer":    env.orgTwoIdP("idp-two"),
		"without issuer": env.orgTwoIdP("idp-two"),
	}
	noIssuer := orgTwo["without issuer"]
	noIssuer.Issuer = ""
	orgTwo["without issuer"] = noIssuer

	for name, own := range orgTwo {
		feeds := map[string][]IdP{
			"org two first": {own, foreign, foreignNoIssuer, ownerless},
			"org one first": {ownerless, foreignNoIssuer, foreign, own},
		}
		for order, feed := range feeds {
			t.Run(name+"/"+order, func(t *testing.T) {
				env.ts.Gw.idpRegistry.rebuild(feed)

				env.expect(t, "/org-two/", env.two.token(t, withoutIss), http.StatusOK)
				env.expect(t, "/org-two/", env.one.token(t), http.StatusForbidden)
				env.expect(t, "/org-two/", env.one.token(t, withoutIss), http.StatusForbidden)
				env.expect(t, "/org-two/", env.one.token(t, withIss("")), http.StatusForbidden)
				env.expect(t, "/org-two/", env.one.token(t, withIss(env.two.issuer)), http.StatusForbidden)

				env.expect(t, "/org-two-default/", env.two.token(t, withoutIss), http.StatusOK)
				env.expect(t, "/org-two-default/", env.one.token(t), http.StatusForbidden)
				env.expect(t, "/org-two-default/", env.one.token(t, withoutIss), http.StatusForbidden)

				env.expect(t, "/org-one/", env.one.token(t), http.StatusOK)
				env.expect(t, "/org-one/", env.one.token(t, withoutIss), http.StatusOK)
				env.expect(t, "/org-one/", env.two.token(t, withoutIss), http.StatusForbidden)
			})
		}
	}

	t.Run("ownerless IdP alone", func(t *testing.T) {
		env.ts.Gw.idpRegistry.rebuild([]IdP{ownerless})
		env.expect(t, "/org-one/", env.one.token(t, withoutIss), http.StatusForbidden)
		env.expect(t, "/org-two/", env.one.token(t, withoutIss), http.StatusForbidden)
	})
}

func TestIdPRegistry_JWT_AllowMissingIssuer_DuplicateIDAcrossOrgs(t *testing.T) {
	env := newIDPIsolationEnv(t, allowMissingIssuer)

	two := env.orgTwoIdP("shared-idp")
	one := env.one.idp("shared-idp", idpOrgOne, map[string]ScopeMapping{
		idpAPIOrgOne: {ScopeToPolicy: map[string]string{"read": env.policyOne}},
	})
	twoNoIssuer, oneNoIssuer := two, one
	twoNoIssuer.Issuer, oneNoIssuer.Issuer = "", ""

	check := func(t *testing.T) {
		t.Helper()
		env.expect(t, "/org-two/", env.two.token(t, withoutIss), http.StatusOK)
		env.expect(t, "/org-two/", env.one.token(t), http.StatusForbidden)
		env.expect(t, "/org-two/", env.one.token(t, withoutIss), http.StatusForbidden)
		env.expect(t, "/org-two-default/", env.one.token(t, withoutIss), http.StatusForbidden)
		env.expect(t, "/org-one/", env.one.token(t, withoutIss), http.StatusOK)
		env.expect(t, "/org-one/", env.two.token(t), http.StatusForbidden)
		env.expect(t, "/org-one/", env.two.token(t, withoutIss), http.StatusForbidden)
	}

	feeds := map[string][]IdP{
		"org two first":                 {two, one},
		"org one first":                 {one, two},
		"org two first, without issuer": {twoNoIssuer, oneNoIssuer},
		"org one first, without issuer": {oneNoIssuer, twoNoIssuer},
	}
	for name, feed := range feeds {
		t.Run(name, func(t *testing.T) {
			env.ts.Gw.idpRegistry.rebuild(feed)
			check(t)
		})
	}
}

// A manual jwt_source stays the only key source under
// allow_unsafe_idp_missing_issuer.
func TestIdPRegistry_JWT_AllowMissingIssuer_ManualSourcePrecedence(t *testing.T) {
	ts := StartTest(allowMissingIssuer)
	defer ts.Close()

	const apiID = "idp-manual-api"
	registryIdP := newIDPTestIssuer(t, "", "kid-registry")

	pID := ts.CreatePolicy(func(p *user.Policy) {
		p.OrgID = idpOrgTwo
		p.AccessRights = map[string]user.AccessDefinition{apiID: {APIID: apiID}}
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.OrgID = idpOrgTwo
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = testHttpJWK
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/manual/"
	})
	ts.Gw.idpRegistry.rebuild([]IdP{registryIdP.idp("idp-1", idpOrgTwo, map[string]ScopeMapping{
		apiID: {ScopeToPolicy: map[string]string{"read": pID}},
	})})
	require.Len(t, ts.Gw.idpRegistry.BindingsForAPI(apiID), 1)

	manualToken := CreateJWKToken(func(tok *jwt.Token) {
		tok.Header[KID] = "12345"
		claims := tok.Claims.(jwt.MapClaims) //nolint:errcheck
		claims["user_id"] = "user"
		claims["policy_id"] = pID
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	})
	registryToken := registryIdP.token(t, withoutIss, func(tok *jwt.Token) {
		tok.Claims.(jwt.MapClaims)["policy_id"] = pID //nolint:errcheck
	})

	_, _ = ts.Run(t, []test.TestCase{
		{Path: "/manual/", Headers: map[string]string{"authorization": manualToken}, Code: http.StatusOK},
		{Path: "/manual/", Headers: map[string]string{"authorization": registryToken}, Code: http.StatusForbidden},
	}...)
}

// A request accepted without an issuer check is logged once per binding per
// rebuild; requests that name the issuer are not.
func TestIdPRegistry_JWT_AllowMissingIssuer_Warns(t *testing.T) {
	env := newIDPIsolationEnv(t, allowMissingIssuer)
	registry := env.ts.Gw.idpRegistry
	registry.rebuild([]IdP{env.orgTwoIdP("idp-two")})

	logger := log
	level := logger.GetLevel()
	originalHooks := make(logrus.LevelHooks)
	for lvl, hooks := range logger.Hooks {
		originalHooks[lvl] = append([]logrus.Hook(nil), hooks...)
	}
	logger.SetLevel(logrus.WarnLevel)
	hook := logrustest.NewLocal(logger)
	t.Cleanup(func() {
		logger.ReplaceHooks(originalHooks)
		logger.SetLevel(level)
	})

	warnings := func() (n int) {
		for _, e := range hook.AllEntries() {
			if e.Level == logrus.WarnLevel && e.Data["prefix"] == "idp-registry" {
				assert.Equal(t, "idp-two", e.Data["client_idp_id"])
				assert.Equal(t, idpOrgTwo, e.Data["org_id"])
				n++
			}
		}
		return n
	}

	env.expect(t, "/org-two/", env.two.token(t), http.StatusOK)
	env.expect(t, "/org-two/", env.one.token(t, withoutIss), http.StatusForbidden)
	assert.Zero(t, warnings())

	env.expect(t, "/org-two/", env.two.token(t, withoutIss), http.StatusOK)
	env.expect(t, "/org-two/", env.two.token(t, withoutIss), http.StatusOK)
	assert.Equal(t, 1, warnings())

	env.expect(t, "/org-two-default/", env.two.token(t, withoutIss), http.StatusOK)
	assert.Equal(t, 2, warnings(), "each API warns once")

	registry.rebuild([]IdP{env.orgTwoIdP("idp-two")})
	env.expect(t, "/org-two/", env.two.token(t, withoutIss), http.StatusOK)
	assert.Equal(t, 3, warnings())
}
