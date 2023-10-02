package gateway

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	headers2 "github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/cache"
	"github.com/TykTechnologies/tyk/test"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/user"
)

type mockStore struct {
	SessionHandler
	//DetailNotFound is used to make mocked SessionDetail return (x,false), as if it don't find the session in the mocked storage.
	DetailNotFound bool
}

var sess = user.SessionState{
	OrgID:       "TestBaseMiddleware_OrgSessionExpiry",
	DataExpires: 110,
}

func (m mockStore) SessionDetail(orgID string, keyName string, hashed bool) (user.SessionState, bool) {
	return sess.Clone(), !m.DetailNotFound
}

func TestBaseMiddleware_OrgSessionExpiry(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	m := BaseMiddleware{
		Spec: &APISpec{
			GlobalConfig: config.Config{
				EnforceOrgDataAge: true,
			},
			OrgSessionManager: mockStore{},
		},
		logger: mainLog,
		Gw:     ts.Gw,
	}
	v := int64(100)
	ts.Gw.ExpiryCache.Set(sess.OrgID, v, cache.DefaultExpiration)

	got := m.OrgSessionExpiry(sess.OrgID)
	assert.Equal(t, v, got)
	ts.Gw.ExpiryCache.Delete(sess.OrgID)

	got = m.OrgSessionExpiry(sess.OrgID)
	assert.Equal(t, sess.DataExpires, got)
	ts.Gw.ExpiryCache.Delete(sess.OrgID)

	m.Spec.OrgSessionManager = mockStore{DetailNotFound: true}
	noOrgSess := "nonexistent_org"
	got = m.OrgSessionExpiry(noOrgSess)
	assert.Equal(t, DEFAULT_ORG_SESSION_EXPIRATION, got)

}

func TestBaseMiddleware_getAuthType(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.AuthConfigs = map[string]apidef.AuthConfig{
		"authToken": {AuthHeaderName: "h1"},
		"basic":     {AuthHeaderName: "h2"},
		"coprocess": {AuthHeaderName: "h3"},
		"hmac":      {AuthHeaderName: "h4"},
		"jwt":       {AuthHeaderName: "h5"},
		"oauth":     {AuthHeaderName: "h6"},
		"oidc":      {AuthHeaderName: "h7"},
	}

	ts := StartTest(nil)
	defer ts.Close()

	baseMid := BaseMiddleware{Spec: spec, Gw: ts.Gw}

	r, _ := http.NewRequest(http.MethodGet, "", nil)
	r.Header.Set("h1", "t1")
	r.Header.Set("h2", "t2")
	r.Header.Set("h3", "t3")
	r.Header.Set("h4", "t4")
	r.Header.Set("h5", "t5")
	r.Header.Set("h6", "t6")
	r.Header.Set("h7", "t7")

	authKey := &AuthKey{BaseMiddleware: baseMid}
	basic := &BasicAuthKeyIsValid{BaseMiddleware: baseMid}
	coprocess := &CoProcessMiddleware{BaseMiddleware: baseMid}
	hmac := &HTTPSignatureValidationMiddleware{BaseMiddleware: baseMid}
	jwt := &JWTMiddleware{BaseMiddleware: baseMid}
	oauth := &Oauth2KeyExists{BaseMiddleware: baseMid}
	oidc := &OpenIDMW{BaseMiddleware: baseMid}

	// test getAuthType
	assert.Equal(t, apidef.AuthTokenType, authKey.getAuthType())
	assert.Equal(t, apidef.BasicType, basic.getAuthType())
	assert.Equal(t, apidef.CoprocessType, coprocess.getAuthType())
	assert.Equal(t, apidef.HMACType, hmac.getAuthType())
	assert.Equal(t, apidef.JWTType, jwt.getAuthType())
	assert.Equal(t, apidef.OAuthType, oauth.getAuthType())
	assert.Equal(t, apidef.OIDCType, oidc.getAuthType())

	// test getAuthToken
	getToken := func(authType string, getAuthToken func(authType string, r *http.Request) (string, apidef.AuthConfig)) string {
		token, _ := getAuthToken(authType, r)
		return token
	}

	assert.Equal(t, "t1", getToken(authKey.getAuthType(), authKey.getAuthToken))
	assert.Equal(t, "t2", getToken(basic.getAuthType(), basic.getAuthToken))
	assert.Equal(t, "t3", getToken(coprocess.getAuthType(), coprocess.getAuthToken))
	assert.Equal(t, "t4", getToken(hmac.getAuthType(), hmac.getAuthToken))
	assert.Equal(t, "t5", getToken(jwt.getAuthType(), jwt.getAuthToken))
	assert.Equal(t, "t6", getToken(oauth.getAuthType(), oauth.getAuthToken))
	assert.Equal(t, "t7", getToken(oidc.getAuthType(), oidc.getAuthToken))
}

func TestBaseMiddleware_getAuthToken(t *testing.T) {
	t.Run("should get token from cookie", func(t *testing.T) {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"authToken": {CookieName: "c1", UseCookie: true},
		}

		ts := StartTest(nil)
		defer ts.Close()

		baseMid := BaseMiddleware{Spec: spec, Gw: ts.Gw}

		r, _ := http.NewRequest(http.MethodGet, "", nil)
		r.AddCookie(&http.Cookie{
			Name:  "c1",
			Value: "t1",
		})

		authKey := &AuthKey{BaseMiddleware: baseMid}

		// test getAuthToken
		getToken := func(authType string, getAuthToken func(authType string, r *http.Request) (string, apidef.AuthConfig)) string {
			token, _ := getAuthToken(authType, r)
			return token
		}

		assert.Equal(t, "t1", getToken(authKey.getAuthType(), authKey.getAuthToken))
	})

	t.Run("should not get token from cookie when use cookie is false", func(t *testing.T) {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"authToken": {CookieName: "c1", UseCookie: false},
		}

		ts := StartTest(nil)
		defer ts.Close()

		baseMid := BaseMiddleware{Spec: spec, Gw: ts.Gw}

		r, _ := http.NewRequest(http.MethodGet, "", nil)
		r.AddCookie(&http.Cookie{
			Name:  "c1",
			Value: "t1",
		})

		authKey := &AuthKey{BaseMiddleware: baseMid}

		// test getAuthToken
		getToken := func(authType string, getAuthToken func(authType string, r *http.Request) (string, apidef.AuthConfig)) string {
			token, _ := getAuthToken(authType, r)
			return token
		}

		assert.Empty(t, getToken(authKey.getAuthType(), authKey.getAuthToken))
	})

	t.Run("should get token from header", func(t *testing.T) {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"authToken": {AuthHeaderName: "h1"},
		}

		ts := StartTest(nil)
		defer ts.Close()

		baseMid := BaseMiddleware{Spec: spec, Gw: ts.Gw}

		r, _ := http.NewRequest(http.MethodGet, "", nil)
		r.Header.Set("h1", "t1")

		authKey := &AuthKey{BaseMiddleware: baseMid}

		// test getAuthToken
		getToken := func(authType string, getAuthToken func(authType string, r *http.Request) (string, apidef.AuthConfig)) string {
			token, _ := getAuthToken(authType, r)
			return token
		}

		assert.Equal(t, "t1", getToken(authKey.getAuthType(), authKey.getAuthToken))
	})

	t.Run("should get token from query", func(t *testing.T) {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"authToken": {ParamName: "q1", UseParam: true},
		}

		ts := StartTest(nil)
		defer ts.Close()

		baseMid := BaseMiddleware{Spec: spec, Gw: ts.Gw}

		r, _ := http.NewRequest(http.MethodGet, "", nil)
		r.URL.RawQuery = "q1=t1"

		authKey := &AuthKey{BaseMiddleware: baseMid}

		// test getAuthToken
		getToken := func(authType string, getAuthToken func(authType string, r *http.Request) (string, apidef.AuthConfig)) string {
			token, _ := getAuthToken(authType, r)
			return token
		}

		assert.Equal(t, "t1", getToken(authKey.getAuthType(), authKey.getAuthToken))
	})

	t.Run("should get token from query when use param is disabled", func(t *testing.T) {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"authToken": {ParamName: "q1", UseParam: false},
		}

		ts := StartTest(nil)
		defer ts.Close()

		baseMid := BaseMiddleware{Spec: spec, Gw: ts.Gw}

		r, _ := http.NewRequest(http.MethodGet, "", nil)
		r.URL.RawQuery = "q1=t1"

		authKey := &AuthKey{BaseMiddleware: baseMid}

		// test getAuthToken
		getToken := func(authType string, getAuthToken func(authType string, r *http.Request) (string, apidef.AuthConfig)) string {
			token, _ := getAuthToken(authType, r)
			return token
		}

		assert.Equal(t, "", getToken(authKey.getAuthType(), authKey.getAuthToken))
	})

}

func TestSessionLimiter_RedisQuotaExceeded_PerAPI(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()
	g.Gw.GlobalSessionManager.Store().DeleteAllKeys()
	defer g.Gw.GlobalSessionManager.Store().DeleteAllKeys()

	apis := BuildAPI(func(spec *APISpec) {
		spec.APIID = "api1"
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/api1/"
	}, func(spec *APISpec) {
		spec.APIID = "api2"
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/api2/"
	}, func(spec *APISpec) {
		spec.APIID = "api3"
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/api3/"
	})

	g.Gw.LoadAPI(apis...)

	const globalQuotaMax int64 = 25

	session, key := g.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			apis[0].APIID: {
				APIID: apis[0].APIID,
				Limit: user.APILimit{
					QuotaMax: 10,
				},
			},
			apis[1].APIID: {
				APIID: apis[1].APIID,
				Limit: user.APILimit{
					QuotaMax: 2,
				},
			},
			apis[2].APIID: {
				APIID: apis[2].APIID,
			},
		}
		s.QuotaMax = globalQuotaMax
		s.QuotaRemaining = globalQuotaMax
	})

	headers := map[string]string{
		headers2.Authorization: key,
	}

	// Check allowance scope is equal to api id because per api is enabled for api1 and api2
	assert.Equal(t, session.AccessRights[apis[0].APIID].AllowanceScope, apis[0].APIID)
	assert.Equal(t, session.AccessRights[apis[1].APIID].AllowanceScope, apis[1].APIID)

	// Check allowcance scope is equal to "" because per api is not enabled for api3
	assert.Equal(t, session.AccessRights[apis[2].APIID].AllowanceScope, "")

	sendReqAndCheckQuota := func(t *testing.T, apiID string, expectedQuotaRemaining int64, perAPI bool) {
		_, _ = g.Run(t, test.TestCase{Path: fmt.Sprintf("/%s/", apiID), Headers: headers, Code: http.StatusOK})

		resp, _ := g.Run(t, test.TestCase{Path: "/tyk/keys/" + key, AdminAuth: true, Code: http.StatusOK})
		bodyInBytes, _ := ioutil.ReadAll(resp.Body)
		var session user.SessionState
		_ = json.Unmarshal(bodyInBytes, &session)

		if perAPI {
			assert.Equal(t, expectedQuotaRemaining, session.AccessRights[apiID].Limit.QuotaRemaining)
			assert.Equal(t, globalQuotaMax, session.QuotaRemaining) // global quota should remain same
		} else {
			assert.Equal(t, expectedQuotaRemaining, session.QuotaRemaining) // if not per api, fallback to global
		}
	}

	// for api1 - per api
	sendReqAndCheckQuota(t, apis[0].APIID, 9, true)
	sendReqAndCheckQuota(t, apis[0].APIID, 8, true)
	sendReqAndCheckQuota(t, apis[0].APIID, 7, true)

	// for api2 - per api
	sendReqAndCheckQuota(t, apis[1].APIID, 1, true)
	sendReqAndCheckQuota(t, apis[1].APIID, 0, true)

	// for api3 - global
	sendReqAndCheckQuota(t, apis[2].APIID, 24, false)
	sendReqAndCheckQuota(t, apis[2].APIID, 23, false)
}

func TestSessionShouldNotAccessToPreviousAPI(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const (
		api1 = "api1"
		api2 = "api2"
	)

	// 1. Create api1, api2 and a policy with api1 and a key with the policy
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = api1
		spec.APIID = api1
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/api1/"
	}, func(spec *APISpec) {
		spec.Name = api2
		spec.APIID = api2
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/api2/"
	})

	pID := ts.CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{api1: {
			APIName: api1,
			APIID:   api1,
		}}
	})

	_, key := ts.CreateSession(func(s *user.SessionState) {
		s.ApplyPolicies = []string{pID}
	})

	headers := map[string]string{
		"Authorization": key,
	}

	// so far so good
	_, _ = ts.Run(t, []test.TestCase{
		{Path: "/api1/", Headers: headers, Code: http.StatusOK},
	}...)

	// 2. Change the pol access rights to api2
	pol, _ := ts.GetPolicyById(pID)
	pol.AccessRights = map[string]user.AccessDefinition{api2: {
		APIName: api2,
		APIID:   api2,
	}}

	ts.SetPolicy(pID, pol)

	// ok, the key doesn't work for api1 and works for api2
	_, _ = ts.Run(t, []test.TestCase{
		{Path: "/api2/", Headers: headers, Code: http.StatusOK},
		{Path: "/api1/", Headers: headers, Code: http.StatusForbidden},
	}...)

	// 3. Remove api2 from the system
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.APIID = api1
		spec.Proxy.ListenPath = "/api1/"
	})

	delete(pol.AccessRights, api2)
	ts.SetPolicy(pID, pol)

	// api1 is not in the pol so not accessible, and api2 is not in the system so not found
	_, _ = ts.Run(t, []test.TestCase{
		{Path: "/api2/", Headers: headers, Code: http.StatusNotFound},
		{Path: "/api1/", Headers: headers, Code: http.StatusForbidden},
	}...)

	// session object returned should not have any access rights
	_, _ = ts.Run(t, test.TestCase{
		AdminAuth: true, Path: "/tyk/keys/" + key, BodyMatchFunc: func(bytes []byte) bool {
			var s user.SessionState
			err := json.Unmarshal(bytes, &s)
			assert.NoError(t, err)

			assert.Len(t, s.AccessRights, 0)

			return true
		}, Code: http.StatusOK,
	})
}
