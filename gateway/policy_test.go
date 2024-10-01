package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
	"time"

	persistentmodel "github.com/TykTechnologies/storage/persistent/model"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/rpc"
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

type RPCDataLoaderMock struct {
	ShouldConnect bool
	Policies      []user.Policy
	Apis          []nestedApiDefinition
}

func (s *RPCDataLoaderMock) Connect() bool {
	return s.ShouldConnect
}

func (s *RPCDataLoaderMock) GetApiDefinitions(orgId string, tags []string) string {
	apiList, err := json.Marshal(s.Apis)
	if err != nil {
		return ""
	}
	return string(apiList)
}
func (s *RPCDataLoaderMock) GetPolicies(orgId string) string {
	policyList, err := json.Marshal(s.Policies)
	if err != nil {
		return ""
	}
	return string(policyList)
}

func Test_LoadPoliciesFromRPC(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	objectID := persistentmodel.NewObjectID()

	t.Run("load policies from RPC - success", func(t *testing.T) {
		mockedStorage := &RPCDataLoaderMock{
			ShouldConnect: true,
			Policies: []user.Policy{
				{MID: objectID, ID: "", OrgID: "org1"},
			},
		}

		polMap, err := ts.Gw.LoadPoliciesFromRPC(mockedStorage, "org1", true)

		assert.NoError(t, err, "error loading policies from RPC:", err)
		assert.Equal(t, 1, len(polMap), "expected 0 policies to be loaded from RPC")
	})

	t.Run("load policies from RPC - success - then fail", func(t *testing.T) {
		mockedStorage := &RPCDataLoaderMock{
			ShouldConnect: true,
			Policies: []user.Policy{
				{MID: objectID, ID: "", OrgID: "org1"},
			},
		}
		// we load the Policies from RPC successfully - it should store the Policies in the backup
		polMap, err := ts.Gw.LoadPoliciesFromRPC(mockedStorage, "org1", true)

		assert.NoError(t, err, "error loading policies from RPC:", err)
		assert.Equal(t, 1, len(polMap), "expected 0 policies to be loaded from RPC")

		// we now simulate a failure to connect to RPC
		mockedStorage.ShouldConnect = false
		rpc.SetEmergencyMode(t, true)
		defer rpc.ResetEmergencyMode()

		// we now try to load the Policies again, and expect it to load the Policies from the backup
		polMap, err = ts.Gw.LoadPoliciesFromRPC(mockedStorage, "org1", true)

		assert.NoError(t, err, "error loading policies from RPC:", err)
		assert.Equal(t, 1, len(polMap), "expected 0 policies to be loaded from RPC")
	})
}
