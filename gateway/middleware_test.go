package gateway

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	headers2 "github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/cache"
	"github.com/TykTechnologies/tyk/internal/uuid"
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

	m := &BaseMiddleware{
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

	baseMid := &BaseMiddleware{Spec: spec, Gw: ts.Gw}

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

		baseMid := &BaseMiddleware{Spec: spec, Gw: ts.Gw}

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

		baseMid := &BaseMiddleware{Spec: spec, Gw: ts.Gw}

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

		baseMid := &BaseMiddleware{Spec: spec, Gw: ts.Gw}

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

		baseMid := &BaseMiddleware{Spec: spec, Gw: ts.Gw}

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

		baseMid := &BaseMiddleware{Spec: spec, Gw: ts.Gw}

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
	t.Skip() // DeleteAllKeys interferes with other tests.

	g := StartTest(nil)
	defer g.Close()

	g.Gw.GlobalSessionManager.Store().DeleteAllKeys()       // exclusive
	defer g.Gw.GlobalSessionManager.Store().DeleteAllKeys() // exclusive

	api := func(spec *APISpec) {
		spec.APIID = uuid.New()
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = fmt.Sprintf("/%s/", spec.APIID)
	}
	apis := BuildAPI(api, api, api)

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

	// Check allowance scope is equal to "" because per api is not enabled for api3
	assert.Equal(t, session.AccessRights[apis[2].APIID].AllowanceScope, "")

	sendReqAndCheckQuota := func(t *testing.T, apiID string, expectedQuotaRemaining int64, perAPI bool) {
		t.Helper()
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

	t.Run("For api1 - per api", func(t *testing.T) {
		sendReqAndCheckQuota(t, apis[0].APIID, 9, true)
		sendReqAndCheckQuota(t, apis[0].APIID, 8, true)
		sendReqAndCheckQuota(t, apis[0].APIID, 7, true)
	})

	t.Run("For api2 - per api", func(t *testing.T) {
		sendReqAndCheckQuota(t, apis[1].APIID, 1, true)
		sendReqAndCheckQuota(t, apis[1].APIID, 0, true)
	})

	t.Run("For api3 - global", func(t *testing.T) {
		sendReqAndCheckQuota(t, apis[2].APIID, 24, false)
		sendReqAndCheckQuota(t, apis[2].APIID, 23, false)
		sendReqAndCheckQuota(t, apis[2].APIID, 22, false)
		sendReqAndCheckQuota(t, apis[2].APIID, 21, false)
		sendReqAndCheckQuota(t, apis[2].APIID, 20, false)
	})
}

func TestCopyAllowedURLs(t *testing.T) {
	testCases := []struct {
		name  string
		input []user.AccessSpec
	}{
		{
			name: "Copy non-empty slice of AccessSpec with non-empty Methods",
			input: []user.AccessSpec{
				{
					URL:     "http://example.com",
					Methods: []string{"GET", "POST"},
				},
				{
					URL:     "http://example.org",
					Methods: []string{"GET"},
				},
			},
		},
		{
			name: "Copy non-empty slice of AccessSpec with empty Methods",
			input: []user.AccessSpec{
				{
					URL:     "http://example.com",
					Methods: []string{},
				},
				{
					URL:     "http://example.org",
					Methods: []string{},
				},
			},
		},
		{
			name: "Copy non-empty slice of AccessSpec with nil Methods",
			input: []user.AccessSpec{
				{
					URL:     "http://example.com",
					Methods: nil,
				},
				{
					URL:     "http://example.org",
					Methods: nil,
				},
			},
		},
		{
			name:  "Copy empty slice of AccessSpec",
			input: []user.AccessSpec{},
		},
		{
			name:  "Copy nil slice of AccessSpec",
			input: []user.AccessSpec(nil),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			copied := copyAllowedURLs(tc.input)
			assert.Equal(t, tc.input, copied)
		})
	}
}

func TestQuotaNotAppliedWithURLRewrite(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	spec := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/quota-test"
		spec.UseKeylessAccess = false
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.UseExtendedPaths = true
			v.ExtendedPaths.URLRewrite = []apidef.URLRewriteMeta{{
				Path:         "/abc",
				Method:       http.MethodGet,
				MatchPattern: "/abc",
				RewriteTo:    "tyk://self/anything",
			}}
		})
	})[0]

	_, authKey := ts.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			spec.APIID: {
				APIName:  spec.Name,
				APIID:    spec.APIID,
				Versions: []string{"default"},
				Limit: user.APILimit{
					QuotaMax:         2,
					QuotaRenewalRate: 3600,
				},
				AllowanceScope: spec.APIID,
			},
		}
		s.OrgID = spec.OrgID
	})

	authorization := map[string]string{
		"Authorization": authKey,
	}
	_, _ = ts.Run(t, []test.TestCase{
		{
			Headers: authorization,
			Path:    "/quota-test/abc",
			Code:    http.StatusOK,
		},
		{
			Headers: authorization,
			Path:    "/quota-test/abc",
			Code:    http.StatusOK,
		},
		{
			Headers: authorization,
			Path:    "/quota-test/abc",
			Code:    http.StatusForbidden,
		},
	}...)
}

func TestBaseMiddleware_OrgSession_StaleWhileRevalidate(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	orgID := "test-org-" + uuid.New()

	// Create org session using mock store
	orgSession := user.SessionState{
		OrgID:          orgID,
		QuotaMax:       100,
		QuotaRemaining: 100,
		Rate:           10,
		Per:            1,
	}

	// Use mock store that returns our test session
	mockOrgStore := mockStore{DetailNotFound: false}

	spec := &APISpec{
		GlobalConfig: config.Config{
			EnforceOrgDataAge: true,
		},
		OrgSessionManager: mockOrgStore,
	}

	baseMid := &BaseMiddleware{
		Spec:   spec,
		Gw:     ts.Gw,
		logger: mainLog,
	}

	t.Run("should cache org session with correct TTL", func(t *testing.T) {
		// Clear cache
		cacheKey := "org:" + orgID
		ts.Gw.SessionCache.Delete(cacheKey)
		orgRefreshInProgress.Delete(orgID)

		// First call - should fetch and cache
		session, found := baseMid.OrgSession(orgID)
		assert.True(t, found, "Should find org session")
		assert.Equal(t, sess.OrgID, session.OrgID)

		// Verify it's cached
		cached, found := ts.Gw.SessionCache.Get(cacheKey)
		assert.True(t, found, "Should be cached")

		entry, ok := cached.(orgCacheEntry)
		assert.True(t, ok, "Cache entry should be orgCacheEntry type")
		assert.Equal(t, sess.OrgID, entry.session.OrgID)
	})

	t.Run("should return fresh cache before soft expiry", func(t *testing.T) {
		cacheKey := "org:" + orgID
		ts.Gw.SessionCache.Delete(cacheKey)
		orgRefreshInProgress.Delete(orgID)

		// Cache a fresh session
		baseMid.cacheOrgSession(orgID, orgSession)

		// Call immediately - should return cached
		session, found := baseMid.OrgSession(orgID)
		assert.True(t, found, "Should find cached session")
		assert.Equal(t, orgID, session.OrgID)

		// Verify no background refresh was triggered (check after small delay)
		time.Sleep(50 * time.Millisecond)
		_, inProgress := orgRefreshInProgress.Load(orgID)
		assert.False(t, inProgress, "Should not trigger background refresh for fresh cache")
	})

	t.Run("should handle fetch timeout for non-existent org", func(t *testing.T) {
		nonExistentOrgID := "timeout-org-" + uuid.New()

		// Use mock that returns not found
		mockNotFound := mockStore{DetailNotFound: true}
		specNotFound := &APISpec{
			GlobalConfig: config.Config{
				EnforceOrgDataAge: true,
			},
			OrgSessionManager: mockNotFound,
		}

		baseMidNotFound := &BaseMiddleware{
			Spec:   specNotFound,
			Gw:     ts.Gw,
			logger: mainLog,
		}

		// Should return false for non-existent org
		_, found := baseMidNotFound.fetchOrgSessionWithTimeout(nonExistentOrgID)
		assert.False(t, found, "Should not find non-existent org")
	})

	t.Run("should handle cold start gracefully", func(t *testing.T) {
		nonExistentOrgID := "cold-start-org-" + uuid.New()
		cacheKey := "org:" + nonExistentOrgID
		ts.Gw.SessionCache.Delete(cacheKey)
		orgRefreshInProgress.Delete(nonExistentOrgID)

		// Use mock that returns not found
		mockNotFound := mockStore{DetailNotFound: true}
		specNotFound := &APISpec{
			GlobalConfig: config.Config{
				EnforceOrgDataAge: true,
			},
			OrgSessionManager: mockNotFound,
		}

		baseMidNotFound := &BaseMiddleware{
			Spec:   specNotFound,
			Gw:     ts.Gw,
			logger: mainLog,
		}

		// Cold start with non-existent org should return quickly (not found)
		_, found := baseMidNotFound.OrgSession(nonExistentOrgID)
		assert.False(t, found, "Should not find non-existent org session")
	})

	t.Run("should handle invalid cache entry type", func(t *testing.T) {
		cacheKey := "org:" + orgID
		ts.Gw.SessionCache.Delete(cacheKey)
		orgRefreshInProgress.Delete(orgID)

		// Store invalid type in cache
		ts.Gw.SessionCache.Set(cacheKey, "invalid-type", cache.DefaultExpiration)

		// Should handle gracefully and fetch fresh
		session, found := baseMid.OrgSession(orgID)

		if found {
			assert.Equal(t, sess.OrgID, session.OrgID, "Should fetch fresh session after invalid cache")
		}

		// Verify invalid entry was replaced with valid entry
		cached, exists := ts.Gw.SessionCache.Get(cacheKey)
		if exists {
			_, isString := cached.(string)
			assert.False(t, isString, "Invalid cache entry should have been replaced")
		}
	})
}
