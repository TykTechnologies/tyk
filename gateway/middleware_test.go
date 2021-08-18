package gateway

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	headers2 "github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/test"
	cache "github.com/pmylund/go-cache"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/user"
)

type mockStore struct {
	SessionHandler
}

var sess = user.SessionState{
	OrgID:       "TestBaseMiddleware_OrgSessionExpiry",
	DataExpires: 110,
}

func (mockStore) SessionDetail(orgID string, keyName string, hashed bool) (user.SessionState, bool) {
	return sess.Clone(), true
}

func TestBaseMiddleware_OrgSessionExpiry(t *testing.T) {
	m := BaseMiddleware{
		Spec: &APISpec{
			GlobalConfig: config.Config{
				EnforceOrgDataAge: true,
			},
			OrgSessionManager: mockStore{},
		},
		logger: mainLog,
	}
	v := int64(100)
	ExpiryCache.Set(sess.OrgID, v, cache.DefaultExpiration)

	got := m.OrgSessionExpiry(sess.OrgID)
	if got != v {
		t.Errorf("expected %d got %d", v, got)
	}
	ExpiryCache.Delete(sess.OrgID)
	got = m.OrgSessionExpiry(sess.OrgID)
	if got != sess.DataExpires {
		t.Errorf("expected %d got %d", sess.DataExpires, got)
	}
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

	baseMid := BaseMiddleware{Spec: spec}

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
	assert.Equal(t, authTokenType, authKey.getAuthType())
	assert.Equal(t, basicType, basic.getAuthType())
	assert.Equal(t, coprocessType, coprocess.getAuthType())
	assert.Equal(t, hmacType, hmac.getAuthType())
	assert.Equal(t, jwtType, jwt.getAuthType())
	assert.Equal(t, oauthType, oauth.getAuthType())
	assert.Equal(t, oidcType, oidc.getAuthType())

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

func TestSessionLimiter_RedisQuotaExceeded_PerAPI(t *testing.T) {
	g := StartTest()
	defer g.Close()
	GlobalSessionManager.Store().DeleteAllKeys()
	defer GlobalSessionManager.Store().DeleteAllKeys()

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

	LoadAPI(apis...)

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
