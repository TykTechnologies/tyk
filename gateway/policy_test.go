package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	persistentmodel "github.com/TykTechnologies/storage/persistent/model"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"

	"github.com/TykTechnologies/tyk/internal/uuid"
)

func TestLoadPoliciesFromDashboardReLogin(t *testing.T) {
	// Test Dashboard
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer ts.Close()

	conf := func(globalConf *config.Config) {
		globalConf.UseDBAppConfigs = false
	}
	g := StartTest(conf)
	defer g.Close()

	// Reset the global dashboard client to ensure test isolation
	g.Gw.resetDashboardClient()

	allowExplicitPolicyID := g.Gw.GetConfig().Policies.AllowExplicitPolicyID
	policyMap, err := g.Gw.LoadPoliciesFromDashboard(ts.URL, "", allowExplicitPolicyID)

	assert.Error(t, ErrPoliciesFetchFailed, err)
	assert.Empty(t, policyMap)
}

func TestApplyPoliciesQuotaAPILimit(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.policiesMu.RLock()
	policy := user.Policy{
		ID:               "two_of_three_with_api_limit",
		Per:              1,
		Rate:             1000,
		QuotaMax:         50,
		QuotaRenewalRate: 3600,
		OrgID:            DefaultOrg,
		Partitions: user.PolicyPartitions{
			PerAPI:    true,
			Quota:     false,
			RateLimit: false,
			Acl:       false,
		},
		AccessRights: map[string]user.AccessDefinition{
			"api1": {
				Versions: []string{"v1"},
				Limit: user.APILimit{
					QuotaMax:         100,
					QuotaRenewalRate: 3600,
					RateLimit: user.RateLimit{
						Rate: 1000,
						Per:  1,
					},
				},
			},
			"api2": {
				Versions: []string{"v1"},
				Limit: user.APILimit{
					QuotaMax:         200,
					QuotaRenewalRate: 3600,
					RateLimit: user.RateLimit{
						Rate: 1000,
						Per:  1,
					},
				},
			},
			"api3": {
				Versions: []string{"v1"},
			},
		},
	}
	ts.Gw.policiesByID = map[string]user.Policy{
		"two_of_three_with_api_limit": policy,
	}
	ts.Gw.policiesMu.RUnlock()

	// load APIs
	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.Name = "api 1"
			spec.APIID = "api1"
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/api1"
			spec.OrgID = DefaultOrg
		},
		func(spec *APISpec) {
			spec.Name = "api 2"
			spec.APIID = "api2"
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/api2"
			spec.OrgID = DefaultOrg
		},
		func(spec *APISpec) {
			spec.Name = "api 3"
			spec.APIID = "api3"
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/api3"
			spec.OrgID = DefaultOrg
		},
	)

	// create test session
	session := &user.SessionState{
		ApplyPolicies: []string{"two_of_three_with_api_limit"},
		OrgID:         DefaultOrg,
		AccessRights: map[string]user.AccessDefinition{
			"api1": {
				APIID:    "api1",
				Versions: []string{"v1"},
			},
			"api2": {
				APIID:    "api2",
				Versions: []string{"v1"},
			},
			"api3": {
				APIID:    "api3",
				Versions: []string{"v1"},
			},
		},
	}

	// create key
	key := uuid.New()
	ts.Run(t, []test.TestCase{
		{Method: http.MethodPost, Path: "/tyk/keys/" + key, Data: session, AdminAuth: true, Code: 200},
	}...)

	// run requests to different APIs
	authHeader := map[string]string{"Authorization": key}
	t.Run("requests to different apis", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			// 2 requests to api1, API limit quota remaining should be 98
			{Method: http.MethodGet, Path: "/api1", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "99"}},
			{Method: http.MethodGet, Path: "/api1", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "98"}},
			// 3 requests to api2, API limit quota remaining should be 197
			{Method: http.MethodGet, Path: "/api2", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "199"}},
			{Method: http.MethodGet, Path: "/api2", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "198"}},
			{Method: http.MethodGet, Path: "/api2", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "197"}},
			// 5 requests to api3, API limit quota remaining should be 45
			{Method: http.MethodGet, Path: "/api3", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "49"}},
			{Method: http.MethodGet, Path: "/api3", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "48"}},
			{Method: http.MethodGet, Path: "/api3", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "47"}},
			{Method: http.MethodGet, Path: "/api3", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "46"}},
			{Method: http.MethodGet, Path: "/api3", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "45"}},
		}...)
	})

	// check key session
	t.Run("Check session key", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{
				Method:    http.MethodGet,
				Path:      fmt.Sprintf("/tyk/keys/%v?org_id=%v", key, DefaultOrg),
				AdminAuth: true,
				Code:      http.StatusOK,
				BodyMatchFunc: func(data []byte) bool {
					sessionData := user.SessionState{}
					if err := json.Unmarshal(data, &sessionData); err != nil {
						t.Log(err.Error())
						return false
					}

					api1Limit := sessionData.AccessRights["api1"].Limit
					if api1Limit.IsEmpty() {
						t.Log("api1 limit is not set")
						return false
					}
					api1LimitExpected := user.APILimit{
						RateLimit: user.RateLimit{
							Rate: 1000,
							Per:  1,
						},
						QuotaMax:         100,
						QuotaRenewalRate: 3600,
						QuotaRenews:      api1Limit.QuotaRenews,
						QuotaRemaining:   98,
					}
					if !reflect.DeepEqual(api1Limit, api1LimitExpected) {
						t.Log("api1 limit received:", api1Limit, "expected:", api1LimitExpected)
						return false
					}
					api2Limit := sessionData.AccessRights["api2"].Limit
					if api2Limit.IsEmpty() {
						t.Log("api2 limit is not set")
						return false
					}
					api2LimitExpected := user.APILimit{
						RateLimit: user.RateLimit{
							Rate: 1000,
							Per:  1,
						},
						QuotaMax:         200,
						QuotaRenewalRate: 3600,
						QuotaRenews:      api2Limit.QuotaRenews,
						QuotaRemaining:   197,
					}
					if !reflect.DeepEqual(api2Limit, api2LimitExpected) {
						t.Log("api2 limit received:", api2Limit, "expected:", api2LimitExpected)
						return false
					}
					api3Limit := sessionData.AccessRights["api3"].Limit
					if api3Limit.IsEmpty() {
						t.Log("api3 limit is not set")
						return false
					}
					api3LimitExpected := user.APILimit{
						RateLimit: user.RateLimit{
							Rate: 1000,
							Per:  1,
						},
						QuotaMax:         50,
						QuotaRenewalRate: 3600,
						QuotaRenews:      api3Limit.QuotaRenews,
						QuotaRemaining:   45,
					}

					if !reflect.DeepEqual(api3Limit, api3LimitExpected) {
						t.Log("api3 limit received:", api3Limit, "expected:", api3LimitExpected)
						return false
					}
					return true
				},
			},
		}...)

	})

	// Reset quota
	t.Run("Reset quota", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{
				Method:    http.MethodPut,
				Path:      fmt.Sprintf("/tyk/keys/%v", key),
				AdminAuth: true,
				Code:      http.StatusOK,
				Data:      session,
			},
			{
				Method:    http.MethodGet,
				Path:      fmt.Sprintf("/tyk/keys/%v?org_id=%v", key, DefaultOrg),
				AdminAuth: true,
				Code:      http.StatusOK,
				BodyMatchFunc: func(data []byte) bool {
					sessionData := user.SessionState{}
					if err := json.Unmarshal(data, &sessionData); err != nil {
						t.Log(err.Error())
						return false
					}
					api1Limit := sessionData.AccessRights["api1"].Limit
					if api1Limit.IsEmpty() {
						t.Error("api1 limit is not set")
						return false
					}

					if api1Limit.QuotaRemaining != 100 {
						t.Error("Should reset quota:", api1Limit.QuotaRemaining)
						return false
					}

					return true
				},
			},
		}...)
	})

}

func TestApplyMultiPolicies(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	policy1 := user.Policy{
		ID:               "policy1",
		Rate:             1000,
		Per:              1,
		QuotaMax:         50,
		QuotaRenewalRate: 3600,
		OrgID:            DefaultOrg,
		AccessRights: map[string]user.AccessDefinition{
			"api1": {
				Versions: []string{"v1"},
			},
		},
	}

	assert.True(t, !policy1.APILimit().IsEmpty())

	policy2 := user.Policy{
		ID:               "policy2",
		Rate:             100,
		Per:              1,
		QuotaMax:         100,
		QuotaRenewalRate: 3600,
		OrgID:            DefaultOrg,
		AccessRights: map[string]user.AccessDefinition{
			"api2": {
				Versions: []string{"v1"},
			},
			"api3": {
				Versions: []string{"v1"},
			},
		},
	}

	assert.True(t, !policy2.APILimit().IsEmpty())

	ts.Gw.policiesMu.Lock()
	ts.Gw.policiesByID = map[string]user.Policy{
		"policy1": policy1,
		"policy2": policy2,
	}
	ts.Gw.policiesMu.Unlock()

	// load APIs
	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.Name = "api 1"
			spec.APIID = "api1"
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/api1"
			spec.OrgID = DefaultOrg
		},
		func(spec *APISpec) {
			spec.Name = "api 2"
			spec.APIID = "api2"
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/api2"
			spec.OrgID = DefaultOrg
		},
		func(spec *APISpec) {
			spec.Name = "api 3"
			spec.APIID = "api3"
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/api3"
			spec.OrgID = DefaultOrg
		},
	)

	// create test session
	session := &user.SessionState{
		ApplyPolicies: []string{"policy1", "policy2"},
		OrgID:         DefaultOrg,
	}

	// create key
	key := uuid.New()
	ts.Run(t, []test.TestCase{
		{
			Method:    http.MethodPost,
			Path:      "/tyk/keys/" + key,
			Data:      session,
			AdminAuth: true,
			Code:      200,
		},
	}...)

	// run requests to different APIs
	authHeader := map[string]string{"Authorization": key}

	t.Run("Requests different apis", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			// 2 requests to api1, API limit quota remaining should be 48
			{Path: "/api1", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "49"}},
			{Path: "/api1", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "48"}},

			// 3 requests to api2, API limit quota remaining should be 197
			{Path: "/api2", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "99"}},
			{Path: "/api2", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "98"}},
			{Path: "/api2", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "97"}},

			// 3 requests to api3, should consume policy2 quota, same as for api2
			{Path: "/api3", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "96"}},
			{Path: "/api3", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "95"}},
			{Path: "/api3", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "94"}},
		}...)

	})

	// check key session
	t.Run("Check key session", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{
				Method:    http.MethodGet,
				Path:      fmt.Sprintf("/tyk/keys/%v?org_id=%v", key, DefaultOrg),
				AdminAuth: true,
				Code:      http.StatusOK,
				BodyMatchFunc: func(data []byte) bool {
					sessionData := user.SessionState{}
					json.Unmarshal(data, &sessionData)

					policy1Expected := user.APILimit{
						RateLimit: user.RateLimit{
							Rate: 1000,
							Per:  1,
						},
						QuotaMax:         50,
						QuotaRenewalRate: 3600,
						QuotaRenews:      sessionData.AccessRights["api1"].Limit.QuotaRenews,
						QuotaRemaining:   48,
					}
					assert.Equal(t, policy1Expected, sessionData.AccessRights["api1"].Limit, "API1 limit do not match")

					policy2Expected := user.APILimit{
						RateLimit: user.RateLimit{
							Rate: 100,
							Per:  1,
						},
						QuotaMax:         100,
						QuotaRenewalRate: 3600,
						QuotaRenews:      sessionData.AccessRights["api2"].Limit.QuotaRenews,
						QuotaRemaining:   94,
					}

					assert.Equal(t, policy2Expected, sessionData.AccessRights["api2"].Limit, "API2 limit do not match")
					assert.Equal(t, policy2Expected, sessionData.AccessRights["api3"].Limit, "API3 limit do not match")

					return true
				},
			},
		}...)

	})

	// Reset quota
	t.Run("Reset quota", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{
				Method:    http.MethodPut,
				Path:      fmt.Sprintf("/tyk/keys/%v", key),
				AdminAuth: true,
				Code:      http.StatusOK,
				Data:      session,
			},
			{
				Method:    http.MethodGet,
				Path:      fmt.Sprintf("/tyk/keys/%v?org_id=%v", key, DefaultOrg),
				AdminAuth: true,
				Code:      http.StatusOK,
				BodyMatchFunc: func(data []byte) bool {
					sessionData := user.SessionState{}
					json.Unmarshal(data, &sessionData)

					assert.EqualValues(t, 50, sessionData.AccessRights["api1"].Limit.QuotaRemaining, "should reset policy1 quota")
					assert.EqualValues(t, 100, sessionData.AccessRights["api2"].Limit.QuotaRemaining, "should reset policy2 quota")
					assert.EqualValues(t, 100, sessionData.AccessRights["api3"].Limit.QuotaRemaining, "should reset policy2 quota")

					return true
				},
			},
		}...)

	})

	// Rate limits before
	t.Run("Rate limits before policy update", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			// 2 requests to api1, API limit quota remaining should be 48
			{Path: "/api1", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "49"}},
			{Path: "/api1", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "48"}},
		}...)
	})

	ts.Gw.policiesMu.RLock()
	policy1.Rate = 1
	policy1.LastUpdated = strconv.Itoa(int(time.Now().Unix() + 1))

	ts.Gw.policiesByID = map[string]user.Policy{
		"policy1": policy1,
		"policy2": policy2,
	}
	ts.Gw.policiesMu.RUnlock()

	// Rate limits after policy update
	t.Run("Rate limits after policy update", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{Path: "/api1", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{header.XRateLimitRemaining: "47"}},
			{Path: "/api1", Headers: authHeader, Code: http.StatusTooManyRequests},
		}...)
	})
}

func TestPerAPIPolicyUpdate(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.policiesMu.RLock()
	policy := user.Policy{
		ID:    "per_api_policy_with_two_apis",
		OrgID: "default",
		Partitions: user.PolicyPartitions{
			PerAPI:    true,
			Quota:     false,
			RateLimit: false,
			Acl:       false,
		},
		AccessRights: map[string]user.AccessDefinition{
			"api1": {
				Versions: []string{"v1"},
			},
			"api2": {
				Versions: []string{"v1"},
			},
		},
	}
	ts.Gw.policiesByID = map[string]user.Policy{
		"per_api_policy_with_two_apis": policy,
	}
	ts.Gw.policiesMu.RUnlock()

	// load APIs
	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.Name = "api 1"
			spec.APIID = "api1"
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/api1"
			spec.OrgID = "default"
		},
		func(spec *APISpec) {
			spec.Name = "api 2"
			spec.APIID = "api2"
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/api2"
			spec.OrgID = "default"
		},
	)

	// create test session
	session := &user.SessionState{
		ApplyPolicies: []string{"per_api_policy_with_two_apis"},
		OrgID:         "default",
		AccessRights: map[string]user.AccessDefinition{
			"api1": {
				APIID:    "api1",
				Versions: []string{"v1"},
			},
			"api2": {
				APIID:    "api2",
				Versions: []string{"v1"},
			},
		},
	}

	// create key
	key := uuid.New()
	ts.Run(t, []test.TestCase{
		{Method: http.MethodPost, Path: "/tyk/keys/" + key, Data: session, AdminAuth: true, Code: 200},
	}...)

	// check key session
	ts.Run(t, []test.TestCase{
		{
			Method:    http.MethodGet,
			Path:      "/tyk/keys/" + key + "?api_id=api1",
			AdminAuth: true,
			Code:      http.StatusOK,
			BodyMatchFunc: func(data []byte) bool {
				sessionData := user.SessionState{}
				if err := json.Unmarshal(data, &sessionData); err != nil {
					t.Log(err.Error())
					return false
				}

				if len(sessionData.AccessRights) != 2 {
					t.Fatalf("expected 2 entries in AccessRights found %d", len(sessionData.AccessRights))
				}

				_, ok1 := sessionData.AccessRights["api1"]
				_, ok2 := sessionData.AccessRights["api2"]

				if !ok1 || !ok2 {
					t.Fatalf("expected api1 and api2 in AccessRights found %v", sessionData.AccessRights)
				}

				return true
			},
		},
	}...)

	//Update policy
	ts.Gw.policiesMu.RLock()
	policy = user.Policy{
		ID:    "per_api_policy_with_two_apis",
		OrgID: "default",
		Partitions: user.PolicyPartitions{
			PerAPI:    true,
			Quota:     false,
			RateLimit: false,
			Acl:       false,
		},
		AccessRights: map[string]user.AccessDefinition{
			"api1": {
				Versions: []string{"v1"},
			},
		},
	}
	ts.Gw.policiesByID = map[string]user.Policy{
		"per_api_policy_with_two_apis": policy,
	}
	ts.Gw.policiesMu.RUnlock()

	ts.Run(t, []test.TestCase{
		{
			Method:    http.MethodGet,
			Path:      "/tyk/keys/" + key + "?api_id=api1",
			AdminAuth: true,
			Code:      http.StatusOK,
			BodyMatchFunc: func(data []byte) bool {
				sessionData := user.SessionState{}
				if err := json.Unmarshal(data, &sessionData); err != nil {
					t.Log(err.Error())
					return false
				}

				if len(sessionData.AccessRights) != 1 {
					t.Fatalf("expected only 1 entry in AccessRights found %d", len(sessionData.AccessRights))
				}

				_, ok1 := sessionData.AccessRights["api1"]

				if !ok1 {
					t.Fatalf("expected api1 in AccessRights found %v", sessionData.AccessRights)
				}

				return true
			},
		},
	}...)
}

func TestParsePoliciesFromRPC(t *testing.T) {

	objectID := persistentmodel.NewObjectID()
	explicitID := "explicit_pol_id"
	tcs := []struct {
		testName      string
		allowExplicit bool
		policy        user.Policy
		expectedID    string
	}{
		{
			testName:      "policy with explicit ID - allow_explicit_id false",
			allowExplicit: false,
			policy:        user.Policy{MID: objectID, ID: explicitID},
			expectedID:    objectID.Hex(),
		},
		{
			testName:      "policy with explicit ID - allow_explicit_id true",
			allowExplicit: true,
			policy:        user.Policy{MID: objectID, ID: explicitID},
			expectedID:    explicitID,
		},
		{
			testName:      "policy without explicit ID - allow_explicit_id false",
			allowExplicit: false,
			policy:        user.Policy{MID: objectID, ID: ""},
			expectedID:    objectID.Hex(),
		},
		{
			testName:      "policy without explicit ID - allow_explicit_id true",
			allowExplicit: true,
			policy:        user.Policy{MID: objectID, ID: ""},
			expectedID:    objectID.Hex(),
		},
	}

	for _, tc := range tcs {
		t.Run(tc.testName, func(t *testing.T) {

			policyList, err := json.Marshal([]user.Policy{tc.policy})
			assert.NoError(t, err, "error unmarshalling policies")

			polMap, errParsing := parsePoliciesFromRPC(string(policyList), tc.allowExplicit)
			assert.NoError(t, errParsing, "error parsing policies from RPC:", errParsing)

			_, ok := polMap[tc.expectedID]
			assert.True(t, ok, "expected policy id", tc.expectedID, " not found after parsing policies")
		})
	}

}

// TestLoadPoliciesFromDashboardAutoRecovery tests that nonce desynchronization
// automatically recovers without manual intervention
func TestLoadPoliciesFromDashboardAutoRecovery(t *testing.T) {
	requestCount := 0
	registrationCount := 0

	// Mock dashboard server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle registration requests
		if strings.Contains(r.URL.Path, "/register/node") {
			registrationCount++
			w.Header().Set("Content-Type", "application/json")
			response := NodeResponseOK{
				Status:  "ok",
				Message: map[string]string{"NodeID": "test-node-id"},
				Nonce:   fmt.Sprintf("nonce-%d", registrationCount),
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		// Handle policy requests
		requestCount++
		
		// First request: return 403 to simulate nonce mismatch
		if requestCount == 1 {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Nonce failed"))
			return
		}

		// Subsequent requests: success
		w.Header().Set("Content-Type", "application/json")
		list := struct {
			Message []DBPolicy `json:"message"`
			Nonce   string     `json:"nonce"`
		}{
			Message: []DBPolicy{},
			Nonce:   "success-nonce",
		}
		json.NewEncoder(w).Encode(list)
	}))
	defer ts.Close()

	// Use simplified config to avoid gateway initialization timeouts
	conf := func(globalConf *config.Config) {
		globalConf.UseDBAppConfigs = false // Simplified setup
		globalConf.NodeSecret = "test-secret"
		globalConf.DBAppConfOptions.ConnectionTimeout = 2
		globalConf.DisableDashboardZeroConf = true
	}
	g := StartTest(conf)
	defer g.Close()

	// Reset the global dashboard client to ensure test isolation
	g.Gw.resetDashboardClient()

	// Set up simplified dashboard service
	g.Gw.DashService = &HTTPDashboardHandler{
		Gw: g.Gw,
		Secret: "test-secret",
		RegistrationEndpoint: ts.URL + "/register/node",
	}

	// Test: Load policies should auto-recover from nonce failure
	policyMap, err := g.Gw.LoadPoliciesFromDashboard(ts.URL, "", false)

	// Should succeed due to auto-recovery
	assert.NoError(t, err, "Auto-recovery should allow successful policy loading")
	assert.NotNil(t, policyMap, "Policy map should be returned after auto-recovery")
	
	// Verify the auto-recovery process happened
	assert.GreaterOrEqual(t, requestCount, 1, "Should have made at least 1 policy request")
}

// TestLoadPoliciesFromDashboardNonceEmptyAfterFailedRecovery tests the scenario
// where the gateway tries to recover from nonce error but creates a "Nonce empty" error
func TestLoadPoliciesFromDashboardNonceEmptyAfterFailedRecovery(t *testing.T) {
	var requestCount int

	// Mock dashboard that simulates the problematic behavior described in the plan
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		
		nonce := r.Header.Get("x-tyk-nonce")
		
		// First request: Nonce mismatch 
		if requestCount == 1 {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Nonce failed"))
			return
		}
		
		// Second request: After gateway clears nonce (simulating current broken recovery)
		if requestCount == 2 && nonce == "" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Authorization failed (Nonce empty)"))
			return
		}

		// Should not reach here in the broken scenario
		w.Header().Set("Content-Type", "application/json")
		list := struct {
			Message []DBPolicy `json:"message"`
			Nonce   string     `json:"nonce"`
		}{
			Message: []DBPolicy{},
			Nonce:   "recovery-nonce",
		}
		json.NewEncoder(w).Encode(list)
	}))
	defer ts.Close()

	conf := func(globalConf *config.Config) {
		globalConf.UseDBAppConfigs = false // Simplified setup
		// Set short timeout for tests to prevent hanging
		globalConf.DBAppConfOptions.ConnectionTimeout = 2
		// Disable zeroconf to prevent blocking
		globalConf.DisableDashboardZeroConf = true
		// Set NodeSecret to prevent Fatal error in Init
		globalConf.NodeSecret = "test-secret"
	}
	g := StartTest(conf)
	defer g.Close()

	// Reset the global dashboard client to ensure test isolation
	g.Gw.resetDashboardClient()

	// Set initial nonce to simulate established session
	g.Gw.ServiceNonce = "old-nonce"

	// First call - should get "Nonce failed"
	policyMap, err := g.Gw.LoadPoliciesFromDashboard(ts.URL, "", false)
	assert.Error(t, err)
	assert.Empty(t, policyMap)

	// Simulate the current broken recovery logic: clear the nonce
	g.Gw.ServiceNonce = ""

	// Second call - should get "Authorization failed (Nonce empty)" 
	policyMap, err = g.Gw.LoadPoliciesFromDashboard(ts.URL, "", false)
	assert.Error(t, err)
	assert.Empty(t, policyMap)
	
	// This demonstrates the current broken state that leads to crash loops
	assert.Equal(t, 2, requestCount, "Should have made exactly 2 requests showing the failure loop")
}

// TestLoadPoliciesFromDashboardInvalidSecret tests Case 2.1 - Invalid Dashboard Secret
func TestLoadPoliciesFromDashboardInvalidSecret(t *testing.T) {
	var requestCount int

	// Mock dashboard that returns "Secret incorrect" error
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Authorization failed (Secret incorrect)"))
	}))
	defer ts.Close()

	conf := func(globalConf *config.Config) {
		globalConf.UseDBAppConfigs = false  // Disable dashboard integration for simpler test
	}
	g := StartTest(conf)
	defer g.Close()

	allowExplicitPolicyID := g.Gw.GetConfig().Policies.AllowExplicitPolicyID
	policyMap, err := g.Gw.LoadPoliciesFromDashboard(ts.URL, "invalid-secret", allowExplicitPolicyID)

	// Should fail with the standard error, NOT trigger nonce recovery
	assert.Error(t, err)
	assert.Equal(t, ErrPoliciesFetchFailed, err)
	assert.Empty(t, policyMap)
	assert.Equal(t, 1, requestCount, "Should make only one request, no retry for invalid secret")
}

// TestLoadPoliciesFromDashboardServerError tests Case 2.3 - Server Error (Redis unavailable simulation)
func TestLoadPoliciesFromDashboardServerError(t *testing.T) {
	var requestCount int

	// Mock dashboard that returns 500 Internal Server Error
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error: Cannot connect to Redis"))
	}))
	defer ts.Close()

	conf := func(globalConf *config.Config) {
		globalConf.UseDBAppConfigs = false  // Disable dashboard integration for simpler test
	}
	g := StartTest(conf)
	defer g.Close()

	allowExplicitPolicyID := g.Gw.GetConfig().Policies.AllowExplicitPolicyID
	policyMap, err := g.Gw.LoadPoliciesFromDashboard(ts.URL, "", allowExplicitPolicyID)

	// Should fail with standard error, NOT trigger nonce recovery
	assert.Error(t, err)
	assert.Equal(t, ErrPoliciesFetchFailed, err)
	assert.Empty(t, policyMap)
	assert.Equal(t, 1, requestCount, "Should make only one request, no retry for server errors")
}

// TestLoadPoliciesFromDashboardTimeoutSimulation tests timeout scenario (Case 1.1 simulation)
func TestLoadPoliciesFromDashboardTimeoutSimulation(t *testing.T) {
	var requestCount int
	var registrationCount int

	// Mock dashboard that simulates: request reaches dashboard, response is lost,
	// gateway retries with stale nonce
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle registration requests
		if strings.Contains(r.URL.Path, "/register/node") {
			registrationCount++
			w.Header().Set("Content-Type", "application/json")
			response := NodeResponseOK{
				Status:  "ok",
				Message: map[string]string{"NodeID": "test-node-id"},
				Nonce:   fmt.Sprintf("nonce-%d", registrationCount),
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		// Handle policy requests
		requestCount++
		
		// First request: simulate timeout by returning nonce failure (gateway retries with stale nonce)
		if requestCount == 1 {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Nonce failed"))
			return
		}

		// Subsequent requests: success after auto-recovery
		w.Header().Set("Content-Type", "application/json")
		list := struct {
			Message []DBPolicy `json:"message"`
			Nonce   string     `json:"nonce"`
		}{
			Message: []DBPolicy{},
			Nonce:   "recovery-success-nonce",
		}
		json.NewEncoder(w).Encode(list)
	}))
	defer ts.Close()

	conf := func(globalConf *config.Config) {
		globalConf.UseDBAppConfigs = false // Simplified setup
		// Set short timeout for tests to prevent hanging
		globalConf.DBAppConfOptions.ConnectionTimeout = 2
		// Disable zeroconf to prevent blocking
		globalConf.DisableDashboardZeroConf = true
		// Set NodeSecret to prevent Fatal error in Init
		globalConf.NodeSecret = "test-secret"
	}
	g := StartTest(conf)
	defer g.Close()

	// Reset the global dashboard client to ensure test isolation
	g.Gw.resetDashboardClient()

	// Set up simplified dashboard service
	g.Gw.DashService = &HTTPDashboardHandler{
		Gw: g.Gw,
		Secret: "test-secret",
		RegistrationEndpoint: ts.URL + "/register/node",
	}

	// Set initial nonce to simulate established session before timeout
	g.Gw.ServiceNonce = "pre-timeout-nonce"

	policyMap, err := g.Gw.LoadPoliciesFromDashboard(ts.URL, "", false)

	// Should succeed due to auto-recovery
	assert.NoError(t, err, "Auto-recovery should handle timeout-induced nonce failure")
	assert.NotNil(t, policyMap, "Policy map should be returned after auto-recovery")
	
	// Verify the auto-recovery process for timeout scenario
	assert.Equal(t, 2, requestCount, "Should make 2 requests (failed retry + recovery)")
	assert.Equal(t, 1, registrationCount, "Should re-register once for recovery")
}

// TestLoadPoliciesFromDashboardNoDashServiceFallback tests graceful fallback when DashService unavailable
func TestLoadPoliciesFromDashboardNoDashServiceFallback(t *testing.T) {
	// Mock dashboard that returns nonce error
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Nonce failed"))
	}))
	defer ts.Close()

	conf := func(globalConf *config.Config) {
		globalConf.UseDBAppConfigs = false  // Disable dashboard integration for simpler test
	}
	g := StartTest(conf)
	defer g.Close()

	// DO NOT set up DashService - simulating environment where it's not available
	g.Gw.DashService = nil

	allowExplicitPolicyID := g.Gw.GetConfig().Policies.AllowExplicitPolicyID
	policyMap, err := g.Gw.LoadPoliciesFromDashboard(ts.URL, "", allowExplicitPolicyID)

	// Should fail gracefully without causing panic
	assert.Error(t, err)
	assert.Equal(t, ErrPoliciesFetchFailed, err)
	assert.Empty(t, policyMap)
}

// TestLoadPoliciesFromDashboardNoNodeIDFound tests that missing node ID error triggers auto-recovery
func TestLoadPoliciesFromDashboardNoNodeIDFound(t *testing.T) {
	requestCount := 0
	registrationCount := 0

	// Mock dashboard server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle registration requests
		if strings.Contains(r.URL.Path, "/register/node") {
			registrationCount++
			w.Header().Set("Content-Type", "application/json")
			response := NodeResponseOK{
				Status:  "ok",
				Message: map[string]string{"NodeID": "test-node-id"},
				Nonce:   fmt.Sprintf("nonce-%d", registrationCount),
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		// Handle policy requests
		requestCount++
		
		// First request: return 403 with "No node ID Found" error
		if requestCount == 1 {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Authorization failed (No node ID Found)"))
			return
		}

		// Subsequent requests: success
		w.Header().Set("Content-Type", "application/json")
		list := struct {
			Message []DBPolicy `json:"message"`
			Nonce   string     `json:"nonce"`
		}{
			Message: []DBPolicy{},
			Nonce:   "success-nonce",
		}
		json.NewEncoder(w).Encode(list)
	}))
	defer ts.Close()

	// Use simplified config to avoid gateway initialization timeouts
	conf := func(globalConf *config.Config) {
		globalConf.UseDBAppConfigs = false // Simplified setup
		globalConf.NodeSecret = "test-secret"
		globalConf.DBAppConfOptions.ConnectionTimeout = 2
		globalConf.DisableDashboardZeroConf = true
	}
	g := StartTest(conf)
	defer g.Close()

	// Reset the global dashboard client to ensure test isolation
	g.Gw.resetDashboardClient()

	// Set up simplified dashboard service
	g.Gw.DashService = &HTTPDashboardHandler{
		Gw: g.Gw,
		Secret: "test-secret",
		RegistrationEndpoint: ts.URL + "/register/node",
	}

	// Test: Load policies should auto-recover from missing node ID
	policyMap, err := g.Gw.LoadPoliciesFromDashboard(ts.URL, "", false)

	// Should succeed due to auto-recovery
	assert.NoError(t, err, "Auto-recovery should allow successful policy loading after node ID error")
	assert.NotNil(t, policyMap, "Policy map should be returned after auto-recovery")
	
	// Verify the auto-recovery process happened
	assert.GreaterOrEqual(t, requestCount, 2, "Should have made at least 2 policy requests")
	assert.GreaterOrEqual(t, registrationCount, 1, "Should have re-registered at least once")
}

// TestLoadPoliciesFromDashboardNetworkErrors tests various network error scenarios
func TestLoadPoliciesFromDashboardNetworkErrors(t *testing.T) {
	testCases := []struct {
		name          string
		serverFunc    func() *httptest.Server
		expectedError string
		description   string
	}{
		{
			name: "Connection Refused",
			serverFunc: func() *httptest.Server {
				// Create and immediately close server to simulate connection refused
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
				ts.Close()
				return ts
			},
			expectedError: "connection refused",
			description:   "Dashboard is completely down",
		},
		{
			name: "Network Timeout",
			serverFunc: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Simulate timeout by sleeping longer than client timeout
					// Gateway timeout is set to 2 seconds in test config
					time.Sleep(3 * time.Second)
				}))
			},
			expectedError: "context deadline exceeded",
			description:   "Request times out before response",
		},
		{
			name: "Connection Dropped Mid-Response",
			serverFunc: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Start writing response then close connection
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					// Force flush to send headers
					if f, ok := w.(http.Flusher); ok {
						f.Flush()
					}
					// Simulate connection drop by hijacking and closing
					if hj, ok := w.(http.Hijacker); ok {
						conn, _, _ := hj.Hijack()
						conn.Close()
					}
				}))
			},
			expectedError: "EOF",
			description:   "Connection drops while reading response",
		},
		{
			name: "Empty Response",
			serverFunc: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Return 200 OK but with no body
					w.WriteHeader(http.StatusOK)
				}))
			},
			expectedError: "EOF",
			description:   "Server returns empty response",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := tc.serverFunc()
			if ts != nil {
				defer ts.Close()
			}

			conf := func(globalConf *config.Config) {
				globalConf.UseDBAppConfigs = false
				// Set a short timeout to make tests run faster
				globalConf.DBAppConfOptions.ConnectionTimeout = 2
			}
			g := StartTest(conf)
			defer g.Close()

			// Test: Load policies should fail with network error
			policyMap, err := g.Gw.LoadPoliciesFromDashboard(ts.URL, "", false)

			// Should fail with appropriate error
			assert.Error(t, err, tc.description)
			assert.Nil(t, policyMap)
			
			// For now, network errors are not auto-recovered
			// This is a potential enhancement for the future
			if tc.expectedError != "" && err != nil {
				assert.Contains(t, err.Error(), tc.expectedError, "Error should indicate network issue")
			}
		})
	}
}

// TestLoadPoliciesFromDashboardNetworkErrorRecovery tests auto-recovery from network errors
func TestLoadPoliciesFromDashboardNetworkErrorRecovery(t *testing.T) {
	requestCount := 0
	registrationCount := 0

	// Mock dashboard server that simulates network error then recovery
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle registration requests
		if strings.Contains(r.URL.Path, "/register/node") {
			registrationCount++
			w.Header().Set("Content-Type", "application/json")
			response := NodeResponseOK{
				Status:  "ok",
				Message: map[string]string{"NodeID": "test-node-id"},
				Nonce:   fmt.Sprintf("nonce-%d", registrationCount),
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		// Handle policy requests
		requestCount++
		
		// First request: simulate connection drop (hijack and close)
		if requestCount == 1 {
			// Simulate load balancer draining connection mid-flight
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
			}
			return
		}

		// Subsequent requests: success after re-registration
		w.Header().Set("Content-Type", "application/json")
		list := struct {
			Message []DBPolicy `json:"message"`
			Nonce   string     `json:"nonce"`
		}{
			Message: []DBPolicy{},
			Nonce:   "success-nonce",
		}
		json.NewEncoder(w).Encode(list)
	}))
	defer ts.Close()

	conf := func(globalConf *config.Config) {
		globalConf.UseDBAppConfigs = false
		globalConf.NodeSecret = "test-secret"
		globalConf.DBAppConfOptions.ConnectionTimeout = 2
		globalConf.DisableDashboardZeroConf = true
	}
	g := StartTest(conf)
	defer g.Close()

	// Reset the global dashboard client to ensure test isolation
	g.Gw.resetDashboardClient()

	// Set up dashboard service
	g.Gw.DashService = &HTTPDashboardHandler{
		Gw: g.Gw,
		Secret: "test-secret",
		RegistrationEndpoint: ts.URL + "/register/node",
	}

	// Test: Load policies should auto-recover from network error
	policyMap, err := g.Gw.LoadPoliciesFromDashboard(ts.URL, "", false)

	// Should succeed due to auto-recovery from network error
	assert.NoError(t, err, "Auto-recovery should handle network errors")
	assert.NotNil(t, policyMap, "Policy map should be returned after network error recovery")
	
	// Verify the auto-recovery process happened
	assert.Equal(t, 2, requestCount, "Should have made 2 policy requests (failed + retry)")
	assert.GreaterOrEqual(t, registrationCount, 1, "Should have re-registered after network error")
}

// TestLoadPoliciesFromDashboardLoadBalancerDrain tests various load balancer drain scenarios
func TestLoadPoliciesFromDashboardLoadBalancerDrain(t *testing.T) {
	testCases := []struct {
		name        string
		drainFunc   func(w http.ResponseWriter, requestCount int)
		description string
	}{
		{
			name: "Connection closed before response",
			drainFunc: func(w http.ResponseWriter, requestCount int) {
				if requestCount == 1 {
					// Close connection immediately
					if hj, ok := w.(http.Hijacker); ok {
						conn, _, _ := hj.Hijack()
						conn.Close()
					}
				}
			},
			description: "LB closes connection before any response",
		},
		{
			name: "Connection closed after partial headers",
			drainFunc: func(w http.ResponseWriter, requestCount int) {
				if requestCount == 1 {
					w.Header().Set("Content-Type", "application/json")
					// Close after headers but before body
					if hj, ok := w.(http.Hijacker); ok {
						conn, _, _ := hj.Hijack()
						conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"))
						conn.Close()
					}
				}
			},
			description: "LB closes connection after sending headers",
		},
		{
			name: "Connection closed during JSON write",
			drainFunc: func(w http.ResponseWriter, requestCount int) {
				if requestCount == 1 {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					// Start writing JSON then close
					w.Write([]byte(`{"message":[`))
					if hj, ok := w.(http.Hijacker); ok {
						conn, _, _ := hj.Hijack()
						conn.Close()
					}
				}
			},
			description: "LB closes connection while writing response body",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			requestCount := 0
			registrationCount := 0

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Handle registration requests
				if strings.Contains(r.URL.Path, "/register/node") {
					registrationCount++
					w.Header().Set("Content-Type", "application/json")
					response := NodeResponseOK{
						Status:  "ok",
						Message: map[string]string{"NodeID": "test-node-id"},
						Nonce:   fmt.Sprintf("nonce-%d", registrationCount),
					}
					json.NewEncoder(w).Encode(response)
					return
				}

				// Handle policy requests
				requestCount++
				
				// Apply drain scenario
				tc.drainFunc(w, requestCount)
				
				// If we didn't drain, return success
				if requestCount > 1 {
					w.Header().Set("Content-Type", "application/json")
					list := struct {
						Message []DBPolicy `json:"message"`
						Nonce   string     `json:"nonce"`
					}{
						Message: []DBPolicy{},
						Nonce:   "success-nonce",
					}
					json.NewEncoder(w).Encode(list)
				}
			}))
			defer ts.Close()

			conf := func(globalConf *config.Config) {
				globalConf.UseDBAppConfigs = false
				globalConf.NodeSecret = "test-secret"
				globalConf.DBAppConfOptions.ConnectionTimeout = 2
			}
			g := StartTest(conf)
			defer g.Close()

			// Set up dashboard service
			g.Gw.DashService = &HTTPDashboardHandler{
				Gw: g.Gw,
				Secret: "test-secret",
				RegistrationEndpoint: ts.URL + "/register/node",
			}

			// Test: Should recover from load balancer drain
			policyMap, err := g.Gw.LoadPoliciesFromDashboard(ts.URL, "", false)

			// Should succeed after recovery
			assert.NoError(t, err, tc.description+" - should recover")
			assert.NotNil(t, policyMap, tc.description+" - should return policies")
			assert.Equal(t, 2, requestCount, tc.description+" - should retry after failure")
			assert.GreaterOrEqual(t, registrationCount, 1, tc.description+" - should re-register")
		})
	}
}
