package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/justinas/alice"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	headers2 "github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/cache"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/test"
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

	t.Run("Returns cached value when present", func(t *testing.T) {
		v := int64(100)
		ts.Gw.ExpiryCache.Set(sess.OrgID, v, cache.DefaultExpiration)

		got := m.OrgSessionExpiry(sess.OrgID)
		assert.Equal(t, v, got)
		ts.Gw.ExpiryCache.Delete(sess.OrgID)
	})

	t.Run("Returns default on cache miss, then fetches in background", func(t *testing.T) {
		// Cache miss, should return default immediately
		got := m.OrgSessionExpiry(sess.OrgID)
		assert.Equal(t, DEFAULT_ORG_SESSION_EXPIRATION, got)

		// Wait for background fetch to complete
		time.Sleep(50 * time.Millisecond)

		// Now should have cached value from background fetch
		got = m.OrgSessionExpiry(sess.OrgID)
		assert.Equal(t, sess.DataExpires, got)
		ts.Gw.ExpiryCache.Delete(sess.OrgID)
	})

	t.Run("Returns default when org session not found", func(t *testing.T) {
		m.Spec.OrgSessionManager = mockStore{DetailNotFound: true}
		noOrgSess := "nonexistent_org"

		got := m.OrgSessionExpiry(noOrgSess)
		assert.Equal(t, DEFAULT_ORG_SESSION_EXPIRATION, got)

		// Wait for background fetch
		time.Sleep(50 * time.Millisecond)

		// Should still return default since org doesn't exist
		got = m.OrgSessionExpiry(noOrgSess)
		assert.Equal(t, DEFAULT_ORG_SESSION_EXPIRATION, got)
	})
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

func TestSessionLimiter_RedisQuotaExceeded_ExpiredAtReset(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	g.Gw.GlobalSessionManager.Store().DeleteAllKeys()
	defer g.Gw.GlobalSessionManager.Store().DeleteAllKeys()

	t.Run("expiredAt is set to now.Add(quotaRenewalRate) when lock succeeds", func(t *testing.T) {
		quotaKey := "test-quota-key-expired-at"
		quotaRenewalRate := int64(3600)
		quotaMax := int64(100)
		expectedTTL := time.Duration(quotaRenewalRate) * time.Second

		limiter := g.Gw.SessionLimiter

		session := &user.SessionState{
			KeyID: "test-key-expired-at",
			AccessRights: map[string]user.AccessDefinition{
				"api1": {
					Limit: user.APILimit{
						QuotaMax:         quotaMax,
						QuotaRenewalRate: quotaRenewalRate,
					},
					AllowanceScope: "",
				},
			},
		}

		req := &http.Request{}

		rawKey := QuotaKeyPrefix + quotaKey
		g.Gw.GlobalSessionManager.Store().DeleteRawKey(rawKey)

		limit := &user.APILimit{
			QuotaMax:         quotaMax,
			QuotaRenewalRate: quotaRenewalRate,
		}

		beforeTime := time.Now()
		blocked := limiter.RedisQuotaExceeded(req, session, quotaKey, "", limit, g.Gw.GlobalSessionManager.Store(), false)
		afterTime := time.Now()

		assert.Equal(t, quotaMax-1, session.QuotaRemaining, "Quota remaining should be quotaMax - 1 after increment")
		assert.Greater(t, session.QuotaRenews, int64(0), "QuotaRenews should be set to a future timestamp")

		expectedRenewTimeMin := beforeTime.Add(expectedTTL).Unix()
		expectedRenewTimeMax := afterTime.Add(expectedTTL).Unix()
		assert.GreaterOrEqual(t, session.QuotaRenews, expectedRenewTimeMin,
			"QuotaRenews should be >= beforeTime + quotaRenewalRate (verifies line 510: expiredAt = now.Add(quotaRenewalRate))")
		assert.LessOrEqual(t, session.QuotaRenews, expectedRenewTimeMax,
			"QuotaRenews should be <= afterTime + quotaRenewalRate (verifies line 510: expiredAt = now.Add(quotaRenewalRate))")

		ttl, err := g.Gw.GlobalSessionManager.Store().GetExp(rawKey)
		if err == nil && ttl > 0 {
			assert.InDelta(t, int64(expectedTTL.Seconds()), ttl, 5,
				"Key TTL should be approximately quotaRenewalRate (verifies line 509: Set(rawKey, 0, quotaRenewalRate))")
		}

		assert.False(t, blocked, "Request should not be blocked when quota is not exceeded")
	})

	t.Run("expiredAt is set correctly for scoped quota", func(t *testing.T) {
		quotaKey := "test-quota-key-scoped-expired-at"
		scope := "scope1"
		quotaRenewalRate := int64(1800)
		quotaMax := int64(50)
		expectedTTL := time.Duration(quotaRenewalRate) * time.Second

		limiter := g.Gw.SessionLimiter

		session := &user.SessionState{
			KeyID: "test-key-scoped-expired-at",
			AccessRights: map[string]user.AccessDefinition{
				"api1": {
					Limit: user.APILimit{
						QuotaMax:         quotaMax,
						QuotaRenewalRate: quotaRenewalRate,
					},
					AllowanceScope: scope,
				},
			},
		}

		req := &http.Request{}

		rawKey := QuotaKeyPrefix + scope + "-" + quotaKey
		g.Gw.GlobalSessionManager.Store().DeleteRawKey(rawKey)

		limit := &user.APILimit{
			QuotaMax:         quotaMax,
			QuotaRenewalRate: quotaRenewalRate,
		}

		beforeTime := time.Now()
		blocked := limiter.RedisQuotaExceeded(req, session, quotaKey, scope, limit, g.Gw.GlobalSessionManager.Store(), false)
		afterTime := time.Now()

		accessDef := session.AccessRights["api1"]
		assert.Equal(t, quotaMax-1, accessDef.Limit.QuotaRemaining, "Quota remaining should be quotaMax - 1 after increment")
		assert.Greater(t, accessDef.Limit.QuotaRenews, int64(0), "QuotaRenews should be set to a future timestamp")

		expectedRenewTimeMin := beforeTime.Add(expectedTTL).Unix()
		expectedRenewTimeMax := afterTime.Add(expectedTTL).Unix()
		assert.GreaterOrEqual(t, accessDef.Limit.QuotaRenews, expectedRenewTimeMin,
			"QuotaRenews should be >= beforeTime + quotaRenewalRate (verifies line 510: expiredAt = now.Add(quotaRenewalRate))")
		assert.LessOrEqual(t, accessDef.Limit.QuotaRenews, expectedRenewTimeMax,
			"QuotaRenews should be <= afterTime + quotaRenewalRate (verifies line 510: expiredAt = now.Add(quotaRenewalRate))")

		assert.False(t, blocked, "Request should not be blocked when quota is not exceeded")
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

func TestRecordAccessLog_TraceID(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	tests := []struct {
		name          string
		otelEnabled   bool
		hasTraceCtx   bool
		expectTraceID bool
	}{
		{
			name:          "OTel disabled - no trace_id field",
			otelEnabled:   false,
			hasTraceCtx:   false,
			expectTraceID: false,
		},
		{
			name:          "OTel enabled, no trace context - no trace_id field",
			otelEnabled:   true,
			hasTraceCtx:   false,
			expectTraceID: false,
		},
		{
			name:          "OTel enabled, valid trace context - trace_id present",
			otelEnabled:   true,
			hasTraceCtx:   true,
			expectTraceID: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger, hook := logrustest.NewNullLogger()

			gwConfig := ts.Gw.GetConfig()
			gwConfig.AccessLogs.Enabled = true
			gwConfig.OpenTelemetry.Enabled = tc.otelEnabled
			ts.Gw.SetConfig(gwConfig)

			spec := &APISpec{
				APIDefinition: &apidef.APIDefinition{},
				GlobalConfig:  gwConfig,
			}

			baseMw := &BaseMiddleware{
				Spec:   spec,
				Gw:     ts.Gw,
				logger: logger.WithField("prefix", "test"),
			}

			req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)

			// Add trace context if needed
			if tc.hasTraceCtx && tc.otelEnabled {
				// Create a real OTel provider and span
				otelCfg := &otel.OpenTelemetry{
					Enabled:  true,
					Exporter: "http",
					Endpoint: "http://localhost:4318", // Won't actually connect
				}
				provider := otel.InitOpenTelemetry(context.Background(), logger, otelCfg, "test-gw", "v1.0.0", false, "", false, nil)
				_, span := provider.Tracer().Start(context.Background(), "test-span")
				defer span.End()

				ctx := otel.ContextWithSpan(req.Context(), span)
				req = req.WithContext(ctx)
			}

			resp := &http.Response{
				StatusCode: http.StatusOK,
			}

			latency := analytics.Latency{
				Total:    100,
				Upstream: 80,
				Gateway:  20,
			}

			baseMw.RecordAccessLog(req, resp, latency)

			// Check the logged fields
			assert.NotEmpty(t, hook.Entries, "Expected a log entry")
			lastEntry := hook.LastEntry()

			_, hasTraceID := lastEntry.Data["trace_id"]
			assert.Equal(t, tc.expectTraceID, hasTraceID, "trace_id field presence mismatch")

			if tc.expectTraceID {
				traceID := lastEntry.Data["trace_id"].(string)
				assert.NotEmpty(t, traceID, "trace_id should not be empty when present")
			}

			hook.Reset()
		})
	}
}

func TestGateway_isDisabledForMCP(t *testing.T) {
	gw := &Gateway{}

	t.Run("RedisCacheMiddleware disabled for MCP APIs", func(t *testing.T) {
		mcpSpec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "mcp-test"
			spec.MarkAsMCP()
		})[0]

		baseMid := &BaseMiddleware{Spec: mcpSpec}
		cacheMW := &RedisCacheMiddleware{
			BaseMiddleware: baseMid,
			store:          nil, // store not needed for this test
		}

		result := gw.isDisabledForMCP(cacheMW)
		assert.True(t, result, "RedisCacheMiddleware should be disabled for MCP APIs")
	})

	t.Run("RedisCacheMiddleware enabled for non-MCP APIs", func(t *testing.T) {
		nonMCPSpec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "regular-api"
		})[0]

		baseMid := &BaseMiddleware{Spec: nonMCPSpec}
		cacheMW := &RedisCacheMiddleware{
			BaseMiddleware: baseMid,
			store:          nil,
		}

		result := gw.isDisabledForMCP(cacheMW)
		assert.False(t, result, "RedisCacheMiddleware should be enabled for non-MCP APIs")
	})

	t.Run("other middleware not affected for MCP APIs", func(t *testing.T) {
		mcpSpec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "mcp-test"
			spec.MarkAsMCP()
		})[0]

		baseMid := &BaseMiddleware{Spec: mcpSpec}
		// Test with a non-restricted middleware (e.g., RequestSigning)
		signingMW := &RequestSigning{BaseMiddleware: baseMid}

		result := gw.isDisabledForMCP(signingMW)
		assert.False(t, result, "Non-restricted middleware should work for MCP APIs")
	})
}

func TestGateway_mwAppendEnabled_MCP(t *testing.T) {
	gw := &Gateway{}

	t.Run("does not append cache middleware for MCP APIs", func(t *testing.T) {
		mcpSpec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "mcp-test"
			spec.CacheOptions.EnableCache = true // Even if enabled in config
			spec.MarkAsMCP()
		})[0]

		baseMid := &BaseMiddleware{Spec: mcpSpec}
		cacheMW := &RedisCacheMiddleware{
			BaseMiddleware: baseMid,
			store:          nil,
		}

		var chain []alice.Constructor
		result := gw.mwAppendEnabled(&chain, cacheMW)

		assert.False(t, result, "mwAppendEnabled should return false for restricted MCP middleware")
		assert.Empty(t, chain, "Chain should be empty - cache middleware should not be added for MCP")
	})

	t.Run("appends cache middleware for non-MCP APIs", func(t *testing.T) {
		nonMCPSpec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "regular-api"
			spec.CacheOptions.EnableCache = true
		})[0]

		baseMid := &BaseMiddleware{Spec: nonMCPSpec, Gw: gw}
		cacheMW := &RedisCacheMiddleware{
			BaseMiddleware: baseMid,
			store:          nil,
		}

		var chain []alice.Constructor
		result := gw.mwAppendEnabled(&chain, cacheMW)

		assert.True(t, result, "mwAppendEnabled should return true for cache on non-MCP APIs")
		assert.Len(t, chain, 1, "Chain should have cache middleware for non-MCP APIs")
	})

	t.Run("appends non-restricted middleware for MCP APIs", func(t *testing.T) {
		mcpSpec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "mcp-test"
			spec.RequestSigning.IsEnabled = true
			spec.MarkAsMCP()
		})[0]

		baseMid := &BaseMiddleware{Spec: mcpSpec, Gw: gw}
		signingMW := &RequestSigning{BaseMiddleware: baseMid}

		var chain []alice.Constructor
		result := gw.mwAppendEnabled(&chain, signingMW)

		assert.True(t, result, "mwAppendEnabled should return true for non-restricted middleware on MCP")
		assert.Len(t, chain, 1, "Chain should have non-restricted middleware for MCP APIs")
	})
}
