package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/user"
)

// Verifies: STK-REQ-051, SYS-REQ-139, SW-REQ-126
// STK-REQ-051:STK-REQ-051-AC-01:acceptance
// SYS-REQ-139:nominal:nominal
// SYS-REQ-139:determinism:nominal
// MCDC SYS-REQ-139: gateway_control_api_operation_terminal=T => TRUE
// SW-REQ-126:nominal:nominal
// SW-REQ-126:determinism:nominal
func TestGatewayControlAPIStatusMessages(t *testing.T) {
	testCases := []struct {
		name string
		msg  apiStatusMessage
		want apiStatusMessage
	}{
		{
			name: "success",
			msg:  apiOk("created"),
			want: apiStatusMessage{Status: "ok", Message: "created"},
		},
		{
			name: "error",
			msg:  apiError("failed"),
			want: apiStatusMessage{Status: "error", Message: "failed"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.msg)
		})
	}
}

// Verifies: STK-REQ-051, SYS-REQ-139, SW-REQ-126
// STK-REQ-051:STK-REQ-051-AC-01:acceptance
// SYS-REQ-139:nominal:nominal
// SYS-REQ-139:encoding_safety:nominal
// SW-REQ-126:nominal:nominal
// SW-REQ-126:encoding_safety:nominal
func TestGatewayControlAPIJSONWrite(t *testing.T) {
	t.Run("structured object", func(t *testing.T) {
		recorder := httptest.NewRecorder()

		doJSONWrite(recorder, http.StatusAccepted, apiOk("queued"))

		require.Equal(t, http.StatusAccepted, recorder.Code)
		assert.Equal(t, header.ApplicationJSON, recorder.Header().Get(header.ContentType))

		var msg apiStatusMessage
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &msg))
		assert.Equal(t, apiStatusMessage{Status: "ok", Message: "queued"}, msg)
	})

	t.Run("preencoded bytes", func(t *testing.T) {
		recorder := httptest.NewRecorder()

		doJSONWrite(recorder, http.StatusOK, []byte(`{"status":"ok","message":"raw"}`))

		require.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, header.ApplicationJSON, recorder.Header().Get(header.ContentType))
		assert.JSONEq(t, `{"status":"ok","message":"raw"}`, recorder.Body.String())
	})
}

// Verifies: STK-REQ-051, SYS-REQ-139, SW-REQ-126
// STK-REQ-051:STK-REQ-051-AC-01:acceptance
// SYS-REQ-139:nominal:nominal
// SYS-REQ-139:error_handling:nominal
// SYS-REQ-139:encoding_safety:nominal
// SW-REQ-126:nominal:nominal
// SW-REQ-126:error_handling:nominal
// SW-REQ-126:encoding_safety:nominal
func TestGatewayControlAPIJSONExport(t *testing.T) {
	t.Run("success download", func(t *testing.T) {
		recorder := httptest.NewRecorder()

		doJSONExport(recorder, http.StatusOK, map[string]string{"status": "ok"}, "apis.json")

		require.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, "application/octet-stream", recorder.Header().Get("Content-Type"))
		assert.Equal(t, `attachment;filename="apis.json"`, recorder.Header().Get("Content-Disposition"))
		assert.JSONEq(t, `{"status":"ok"}`, recorder.Body.String())
	})

	t.Run("non success delegates to json writer", func(t *testing.T) {
		recorder := httptest.NewRecorder()

		doJSONExport(recorder, http.StatusBadRequest, apiError("bad"), "ignored.json")

		require.Equal(t, http.StatusBadRequest, recorder.Code)
		assert.Equal(t, header.ApplicationJSON, recorder.Header().Get(header.ContentType))
		assert.JSONEq(t, `{"status":"error","message":"bad"}`, recorder.Body.String())
	})
}

// Verifies: STK-REQ-051, SYS-REQ-139, SW-REQ-126
// STK-REQ-051:STK-REQ-051-AC-01:acceptance
// SYS-REQ-139:boundary:nominal
// SYS-REQ-139:error_handling:nominal
// SW-REQ-126:boundary:nominal
// SW-REQ-126:error_handling:nominal
func TestGatewayControlAPIMethodNotAllowedAndSecureHeaders(t *testing.T) {
	t.Run("method not allowed", func(t *testing.T) {
		recorder := httptest.NewRecorder()

		MethodNotAllowedHandler{}.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/tyk", nil))

		require.Equal(t, http.StatusMethodNotAllowed, recorder.Code)
		assert.JSONEq(t, `{"status":"error","message":"Method not supported"}`, recorder.Body.String())
	})

	t.Run("secure and cache headers", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		called := false
		handler := addSecureAndCacheHeaders(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		})

		handler(recorder, httptest.NewRequest(http.MethodGet, "/tyk", nil))

		require.True(t, called)
		require.Equal(t, http.StatusNoContent, recorder.Code)
		assert.Equal(t, "nosniff", recorder.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "1; mode=block", recorder.Header().Get("X-XSS-Protection"))
		assert.Equal(t, "DENY", recorder.Header().Get("X-Frame-Options"))
		assert.True(t, strings.Contains(recorder.Header().Get("Strict-Transport-Security"), "includeSubDomains"))
		assert.Equal(t, "no-cache, no-store, must-revalidate", recorder.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", recorder.Header().Get("Pragma"))
		assert.Equal(t, "0", recorder.Header().Get("Expires"))
	})
}

// Verifies: STK-REQ-051, SYS-REQ-139, SW-REQ-126
// STK-REQ-051:STK-REQ-051-AC-01:acceptance
// SYS-REQ-139:nominal:nominal
// SYS-REQ-139:error_handling:nominal
// SW-REQ-126:nominal:nominal
// SW-REQ-126:error_handling:nominal
func TestGatewayControlAPIAllowMethods(t *testing.T) {
	t.Run("allowed method invokes handler", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		called := false
		handler := allowMethods(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusAccepted)
		}, http.MethodGet, http.MethodPost)

		handler(recorder, httptest.NewRequest(http.MethodPost, "/tyk", nil))

		require.True(t, called)
		assert.Equal(t, http.StatusAccepted, recorder.Code)
	})

	t.Run("unsupported method returns json error", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		handler := allowMethods(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		}, http.MethodGet)

		handler(recorder, httptest.NewRequest(http.MethodDelete, "/tyk", nil))

		require.Equal(t, http.StatusMethodNotAllowed, recorder.Code)
		assert.JSONEq(t, `{"status":"error","message":"Method not supported"}`, recorder.Body.String())
	})
}

// Verifies: STK-REQ-051, SYS-REQ-139, SW-REQ-126
// STK-REQ-051:STK-REQ-051-AC-01:acceptance
// SYS-REQ-139:nominal:nominal
// SYS-REQ-139:boundary:nominal
// SYS-REQ-139:determinism:nominal
// SW-REQ-126:nominal:nominal
// SW-REQ-126:boundary:nominal
// SW-REQ-126:determinism:nominal
func TestGatewayControlAPIOrgLookupHelpers(t *testing.T) {
	specs := BuildAPI(
		func(spec *APISpec) {
			spec.APIID = "api-a"
			spec.OrgID = "org-a"
		},
		func(spec *APISpec) {
			spec.APIID = "api-b"
			spec.OrgID = "org-b"
		},
		func(spec *APISpec) {
			spec.APIID = "api-c"
			spec.OrgID = "org-a"
		},
	)
	gw := &Gateway{
		apisByID: map[string]*APISpec{
			"api-a": specs[0],
			"api-b": specs[1],
			"api-c": specs[2],
		},
	}

	t.Run("get spec for matching org", func(t *testing.T) {
		spec := gw.getSpecForOrg("org-b")

		require.NotNil(t, spec)
		assert.Equal(t, "api-b", spec.APIID)
	})

	t.Run("get spec falls back when org missing", func(t *testing.T) {
		spec := gw.getSpecForOrg("missing-org")

		require.NotNil(t, spec)
		assert.Contains(t, []string{"api-a", "api-b", "api-c"}, spec.APIID)
	})

	t.Run("get spec returns nil with no apis", func(t *testing.T) {
		empty := &Gateway{apisByID: map[string]*APISpec{}}

		assert.Nil(t, empty.getSpecForOrg("org-a"))
	})

	t.Run("list api ids for org", func(t *testing.T) {
		ids := gw.getApisIdsForOrg("org-a")

		assert.ElementsMatch(t, []string{"api-a", "api-c"}, ids)
	})

	t.Run("list all api ids", func(t *testing.T) {
		ids := gw.getApisIdsForOrg("")

		assert.ElementsMatch(t, []string{"api-a", "api-b", "api-c"}, ids)
	})
}

// Verifies: STK-REQ-052, SYS-REQ-140, SW-REQ-127
// STK-REQ-052:STK-REQ-052-AC-01:acceptance
// SYS-REQ-140:nominal:nominal
// SYS-REQ-140:boundary:nominal
// SYS-REQ-140:error_handling:nominal
// SYS-REQ-140:determinism:nominal
// MCDC SYS-REQ-140: gateway_session_lifecycle_operation_terminal=T => TRUE
// SW-REQ-127:nominal:nominal
// SW-REQ-127:boundary:nominal
// SW-REQ-127:error_handling:nominal
// SW-REQ-127:determinism:nominal
func TestGatewaySessionLifecycleTrialPeriod(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	policyID := ts.CreatePolicy(func(p *user.Policy) {
		p.KeyExpiresIn = 300
		p.PostExpiryAction = user.PostExpiryActionRetain
		p.PostExpiryGracePeriod = 45
	})

	existingSession := CreateStandardSession()
	require.NoError(t, ts.Gw.GlobalSessionManager.UpdateSession("existing-key", existingSession, 60, false))

	testCases := []struct {
		name        string
		keyName     string
		policyIDs   []string
		wantExpiry  bool
		wantPostExp bool
	}{
		{
			name:        "new key receives policy trial expiry and post expiry fields",
			keyName:     "new-key",
			policyIDs:   []string{policyID},
			wantExpiry:  true,
			wantPostExp: true,
		},
		{
			name:        "existing key keeps current expiry but receives post expiry fields",
			keyName:     "existing-key",
			policyIDs:   []string{policyID},
			wantPostExp: true,
		},
		{
			name:      "missing policy leaves session unchanged",
			keyName:   "missing-policy-key",
			policyIDs: []string{"missing-policy"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session := CreateStandardSession()
			session.Expires = -1
			session.ApplyPolicies = tc.policyIDs

			before := time.Now().Unix()
			ts.Gw.checkAndApplyTrialPeriod(tc.keyName, session, false)

			if tc.wantExpiry {
				assert.GreaterOrEqual(t, session.Expires, before+300)
				assert.LessOrEqual(t, session.Expires, time.Now().Unix()+305)
			} else {
				assert.Equal(t, int64(-1), session.Expires)
			}

			if tc.wantPostExp {
				assert.Equal(t, user.PostExpiryActionRetain, session.PostExpiryAction)
				assert.Equal(t, int64(45), session.PostExpiryGracePeriod)
			} else {
				assert.Empty(t, session.PostExpiryAction)
				assert.Zero(t, session.PostExpiryGracePeriod)
			}
		})
	}
}

// Verifies: STK-REQ-052, SYS-REQ-140, SW-REQ-127
// STK-REQ-052:STK-REQ-052-AC-01:acceptance
// SYS-REQ-140:nominal:nominal
// SYS-REQ-140:determinism:nominal
// SW-REQ-127:nominal:nominal
// SW-REQ-127:determinism:nominal
func TestGatewaySessionLifecyclePolicySave(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "save-api"
		spec.OrgID = "default"
		spec.SessionLifetime = 120
	})

	session := CreateStandardSession()
	session.AccessRights = map[string]user.AccessDefinition{
		"save-api": {APIID: "save-api", Versions: []string{"Default"}},
	}

	require.NoError(t, ts.Gw.applyPoliciesAndSave("save-key", session, ts.Gw.getApiSpec("save-api"), false))

	stored, found := ts.Gw.GlobalSessionManager.SessionDetail("default", "save-key", false)
	require.True(t, found)
	assert.Equal(t, session.AccessRights, stored.AccessRights)
}

// Verifies: STK-REQ-052, SYS-REQ-140, SW-REQ-127
// STK-REQ-052:STK-REQ-052-AC-01:acceptance
// STK-REQ-052:error_handling:negative
// SYS-REQ-140:error_handling:negative
// SW-REQ-127:error_handling:negative
func TestGatewaySessionLifecyclePolicySaveRejectsPolicyErrors(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "error-api"
		spec.OrgID = "default"
	})

	policyID := ts.CreatePolicy(func(p *user.Policy) {
		p.OrgID = "other-org"
		p.AccessRights = map[string]user.AccessDefinition{
			"error-api": {APIID: "error-api", Versions: []string{"Default"}},
		}
	})

	session := CreateStandardSession()
	session.ApplyPolicies = []string{policyID}
	session.AccessRights = map[string]user.AccessDefinition{
		"error-api": {APIID: "error-api", Versions: []string{"Default"}},
	}

	err := ts.Gw.applyPoliciesAndSave("policy-error-key", session, ts.Gw.getApiSpec("error-api"), false)

	require.Error(t, err)
	_, found := ts.Gw.GlobalSessionManager.SessionDetail("default", "policy-error-key", false)
	assert.False(t, found)
}

// Verifies: STK-REQ-052, SYS-REQ-140, SW-REQ-127
// STK-REQ-052:STK-REQ-052-AC-01:acceptance
// SYS-REQ-140:nominal:nominal
// SYS-REQ-140:boundary:nominal
// SYS-REQ-140:determinism:nominal
// SW-REQ-127:nominal:nominal
// SW-REQ-127:boundary:nominal
// SW-REQ-127:determinism:nominal
func TestGatewaySessionLifecycleAccessRightsAndLimits(t *testing.T) {
	specs := BuildAPI(
		func(spec *APISpec) {
			spec.APIID = "api-a"
		},
		func(spec *APISpec) {
			spec.APIID = "api-b"
		},
	)
	gw := &Gateway{
		apisByID: map[string]*APISpec{
			"api-a": specs[0],
			"api-b": specs[1],
		},
	}

	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-a":       {APIID: "api-a"},
			"missing-api": {APIID: "missing-api"},
			"api-b":       {APIID: "api-b"},
		},
	}

	gotSpecs := gw.GetApiSpecsFromAccessRights(session)
	gotIDs := make([]string, 0, len(gotSpecs))
	for _, spec := range gotSpecs {
		gotIDs = append(gotIDs, spec.APIID)
	}
	assert.ElementsMatch(t, []string{"api-a", "api-b"}, gotIDs)
	assert.Empty(t, gw.GetApiSpecsFromAccessRights(nil))

	accessRights := map[string]user.AccessDefinition{
		"zero-limit": {APIID: "zero-limit", Limit: user.APILimit{}},
		"rate-limit": {
			APIID: "rate-limit",
			Limit: user.APILimit{RateLimit: user.RateLimit{Rate: 10, Per: 1}},
		},
	}
	resetAPILimits(accessRights)

	assert.Equal(t, user.APILimit{}, accessRights["zero-limit"].Limit)
	assert.Equal(t, user.APILimit{RateLimit: user.RateLimit{Rate: 10, Per: 1}}, accessRights["rate-limit"].Limit)
}
