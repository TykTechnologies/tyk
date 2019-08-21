package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/lonelycode/go-uuid/uuid"

	"github.com/TykTechnologies/tyk/test"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/user"
)

func TestLoadPoliciesFromDashboardReLogin(t *testing.T) {
	// Test Dashboard
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer ts.Close()

	globalConf := config.Global()
	oldUseDBAppConfigs := globalConf.UseDBAppConfigs
	globalConf.UseDBAppConfigs = false
	config.SetGlobal(globalConf)

	defer func() {
		globalConf.UseDBAppConfigs = oldUseDBAppConfigs
		config.SetGlobal(globalConf)
	}()

	allowExplicitPolicyID := config.Global().Policies.AllowExplicitPolicyID

	policyMap := LoadPoliciesFromDashboard(ts.URL, "", allowExplicitPolicyID)

	if policyMap != nil {
		t.Error("Should be nil because got back 403 from Dashboard")
	}
}

type dummySessionManager struct {
	DefaultSessionManager
}

func (*dummySessionManager) UpdateSession(key string, sess *user.SessionState, ttl int64, hashed bool) error {
	return nil
}

type testApplyPoliciesData struct {
	name      string
	policies  []string
	errMatch  string                               // substring
	sessMatch func(*testing.T, *user.SessionState) // ignored if nil
}

func testPrepareApplyPolicies() (*BaseMiddleware, []testApplyPoliciesData) {
	policiesMu.RLock()
	policiesByID = map[string]user.Policy{
		"nonpart1": {},
		"nonpart2": {},
		"difforg":  {OrgID: "different"},
		"tags1": {
			Partitions: user.PolicyPartitions{Quota: true},
			Tags:       []string{"tagA"},
		},
		"tags2": {
			Partitions: user.PolicyPartitions{RateLimit: true},
			Tags:       []string{"tagX", "tagY"},
		},
		"inactive1": {
			Partitions: user.PolicyPartitions{RateLimit: true},
			IsInactive: true,
		},
		"inactive2": {
			Partitions: user.PolicyPartitions{Quota: true},
			IsInactive: true,
		},
		"quota1": {
			Partitions: user.PolicyPartitions{Quota: true},
			QuotaMax:   2,
		},
		"quota2": {Partitions: user.PolicyPartitions{Quota: true}},
		"rate1": {
			Partitions: user.PolicyPartitions{RateLimit: true},
			Rate:       3,
		},
		"rate2": {Partitions: user.PolicyPartitions{RateLimit: true}},
		"acl1": {
			Partitions:   user.PolicyPartitions{Acl: true},
			AccessRights: map[string]user.AccessDefinition{"a": {}},
		},
		"acl2": {
			Partitions:   user.PolicyPartitions{Acl: true},
			AccessRights: map[string]user.AccessDefinition{"b": {}},
		},
		"acl3": {
			AccessRights: map[string]user.AccessDefinition{"c": {}},
		},
		"per_api_and_partitions": {
			ID: "per_api_and_partitions",
			Partitions: user.PolicyPartitions{
				PerAPI:    true,
				Quota:     true,
				RateLimit: true,
				Acl:       true,
			},
			AccessRights: map[string]user.AccessDefinition{"d": {
				Limit: &user.APILimit{
					QuotaMax:         1000,
					QuotaRenewalRate: 3600,
					Rate:             20,
					Per:              1,
				},
			}},
		},
		"per_api_and_some_partitions": {
			ID: "per_api_and_some_partitions",
			Partitions: user.PolicyPartitions{
				PerAPI:    true,
				Quota:     false,
				RateLimit: true,
				Acl:       false,
			},
			AccessRights: map[string]user.AccessDefinition{"d": {
				Limit: &user.APILimit{
					QuotaMax:         1000,
					QuotaRenewalRate: 3600,
					Rate:             20,
					Per:              1,
				},
			}},
		},
		"per_api_and_no_other_partitions": {
			ID: "per_api_and_no_other_partitions",
			Partitions: user.PolicyPartitions{
				PerAPI:    true,
				Quota:     false,
				RateLimit: false,
				Acl:       false,
			},
			AccessRights: map[string]user.AccessDefinition{
				"d": {
					Limit: &user.APILimit{
						QuotaMax:         1000,
						QuotaRenewalRate: 3600,
						Rate:             20,
						Per:              1,
					},
				},
				"c": {
					Limit: &user.APILimit{
						QuotaMax: -1,
						Rate:     2000,
						Per:      60,
					},
				},
			},
		},
		"per_api_with_the_same_api": {
			ID: "per_api_with_the_same_api",
			Partitions: user.PolicyPartitions{
				PerAPI:    true,
				Quota:     false,
				RateLimit: false,
				Acl:       false,
			},
			AccessRights: map[string]user.AccessDefinition{
				"d": {
					Limit: &user.APILimit{
						QuotaMax:         5000,
						QuotaRenewalRate: 3600,
						Rate:             200,
						Per:              10,
					},
				},
			},
		},
		"per_api_with_limit_set_from_policy": {
			ID:       "per_api_with_limit_set_from_policy",
			QuotaMax: -1,
			Rate:     300,
			Per:      1,
			Partitions: user.PolicyPartitions{
				PerAPI:    true,
				Quota:     false,
				RateLimit: false,
				Acl:       false,
			},
			AccessRights: map[string]user.AccessDefinition{
				"d": {
					Limit: &user.APILimit{
						QuotaMax:         5000,
						QuotaRenewalRate: 3600,
						Rate:             200,
						Per:              10,
					},
				},
				"e": {},
			},
		},
	}
	policiesMu.RUnlock()
	bmid := &BaseMiddleware{Spec: &APISpec{
		APIDefinition:  &apidef.APIDefinition{},
		SessionManager: &dummySessionManager{},
	}}
	tests := []testApplyPoliciesData{
		{
			"Empty", nil,
			"", nil,
		},
		{
			"Single", []string{"nonpart1"},
			"", nil,
		},
		{
			"Missing", []string{"nonexistent"},
			"not found", nil,
		},
		{
			"DiffOrg", []string{"difforg"},
			"different org", nil,
		},
		{
			"MultiNonPart", []string{"nonpart1", "nonpart2"},
			"any are non-part", nil,
		},
		{
			"NonpartAndPart", []string{"nonpart1", "quota1"},
			"any are non-part", nil,
		},
		{
			"TagMerge", []string{"tags1", "tags2"},
			"", func(t *testing.T, s *user.SessionState) {
				want := []string{"tagA", "tagX", "tagY"}
				sort.Strings(s.Tags)
				if !reflect.DeepEqual(want, s.Tags) {
					t.Fatalf("want Tags %v, got %v", want, s.Tags)
				}
			},
		},
		{
			"InactiveMergeOne", []string{"tags1", "inactive1"},
			"", func(t *testing.T, s *user.SessionState) {
				if !s.IsInactive {
					t.Fatalf("want IsInactive to be true")
				}
			},
		},
		{
			"InactiveMergeAll", []string{"inactive1", "inactive2"},
			"", func(t *testing.T, s *user.SessionState) {
				if !s.IsInactive {
					t.Fatalf("want IsInactive to be true")
				}
			},
		},
		{
			"QuotaPart", []string{"quota1"},
			"", func(t *testing.T, s *user.SessionState) {
				if s.QuotaMax != 2 {
					t.Fatalf("want QuotaMax to be 2")
				}
			},
		},
		{
			"QuotaParts", []string{"quota1", "quota2"},
			"multiple quota policies", nil,
		},
		{
			"RatePart", []string{"rate1"},
			"", func(t *testing.T, s *user.SessionState) {
				if s.Rate != 3 {
					t.Fatalf("want Rate to be 3")
				}
			},
		},
		{
			"RateParts", []string{"rate1", "rate2"},
			"multiple rate limit policies", nil,
		},
		{
			"AclPart", []string{"acl1"},
			"", func(t *testing.T, s *user.SessionState) {
				want := map[string]user.AccessDefinition{"a": {}}
				if !reflect.DeepEqual(want, s.AccessRights) {
					t.Fatalf("want %v got %v", want, s.AccessRights)
				}
			},
		},
		{
			"AclPart", []string{"acl1", "acl2"},
			"", func(t *testing.T, s *user.SessionState) {
				want := map[string]user.AccessDefinition{"a": {}, "b": {}}
				if !reflect.DeepEqual(want, s.AccessRights) {
					t.Fatalf("want %v got %v", want, s.AccessRights)
				}
			},
		},
		{
			"RightsUpdate", []string{"acl3"},
			"", func(t *testing.T, s *user.SessionState) {
				newPolicy := user.Policy{
					AccessRights: map[string]user.AccessDefinition{"a": {}, "b": {}, "c": {}},
				}
				policiesMu.Lock()
				policiesByID["acl3"] = newPolicy
				policiesMu.Unlock()
				err := bmid.ApplyPolicies(s)
				if err != nil {
					t.Fatalf("couldn't apply policy: %s", err.Error())
				}
				want := newPolicy.AccessRights
				if !reflect.DeepEqual(want, s.AccessRights) {
					t.Fatalf("want %v got %v", want, s.AccessRights)
				}
			},
		},
		{
			name:     "Per API is set with other partitions to true",
			policies: []string{"per_api_and_partitions"},
			errMatch: "cannot apply policy per_api_and_partitions which has per_api and any of partitions set",
		},
		{
			name:     "Per API is set to true with some partitions set to true",
			policies: []string{"per_api_and_some_partitions"},
			errMatch: "cannot apply policy per_api_and_some_partitions which has per_api and any of partitions set",
		},
		{
			name:     "Per API is set to true with no other partitions set to true",
			policies: []string{"per_api_and_no_other_partitions"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				want := map[string]user.AccessDefinition{
					"d": {
						Limit: &user.APILimit{
							QuotaMax:         1000,
							QuotaRenewalRate: 3600,
							Rate:             20,
							Per:              1,
						},
					},
					"c": {
						Limit: &user.APILimit{
							QuotaMax: -1,
							Rate:     2000,
							Per:      60,
						},
					},
				}
				if !reflect.DeepEqual(want, s.AccessRights) {
					t.Fatalf("want %v got %v", want, s.AccessRights)
				}
			},
		},
		{
			name:     "several policies with Per API set to true but specifying limit for the same API",
			policies: []string{"per_api_and_no_other_partitions", "per_api_with_the_same_api"},
			errMatch: "cannot apply multiple policies for API: d",
		},
		{
			name:     "several policies, mixed the one which has Per API set to true and partitioned ones",
			policies: []string{"per_api_and_no_other_partitions", "quota1"},
			errMatch: "cannot apply multiple policies when some are partitioned and some have per_api set",
		},
		{
			name:     "several policies, mixed the one which has Per API set to true and partitioned ones (different order)",
			policies: []string{"rate1", "per_api_and_no_other_partitions"},
			errMatch: "cannot apply multiple policies when some have per_api set and some are partitioned",
		},
		{
			name:     "Per API is set to true and some API gets limit set from policy's fields",
			policies: []string{"per_api_with_limit_set_from_policy"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				want := map[string]user.AccessDefinition{
					"d": {
						Limit: &user.APILimit{
							QuotaMax:         5000,
							QuotaRenewalRate: 3600,
							Rate:             200,
							Per:              10,
						},
					},
					"e": {
						Limit: &user.APILimit{
							QuotaMax:    -1,
							Rate:        300,
							Per:         1,
							SetByPolicy: true,
						},
					},
				}
				if !reflect.DeepEqual(want, s.AccessRights) {
					t.Fatalf("want %v got %v", want, s.AccessRights)
				}
			},
		},
	}

	return bmid, tests
}

func TestApplyPolicies(t *testing.T) {
	bmid, tests := testPrepareApplyPolicies()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sess := &user.SessionState{}
			sess.SetPolicies(tc.policies...)
			errStr := ""
			if err := bmid.ApplyPolicies(sess); err != nil {
				errStr = err.Error()
			}
			if tc.errMatch == "" && errStr != "" {
				t.Fatalf("didn't want err but got %s", errStr)
			} else if !strings.Contains(errStr, tc.errMatch) {
				t.Fatalf("error %q doesn't match %q",
					errStr, tc.errMatch)
			}
			if tc.sessMatch != nil {
				tc.sessMatch(t, sess)
			}
		})
	}
}

func BenchmarkApplyPolicies(b *testing.B) {
	b.ReportAllocs()

	bmid, tests := testPrepareApplyPolicies()

	for i := 0; i < b.N; i++ {
		for _, tc := range tests {
			sess := &user.SessionState{}
			sess.SetPolicies(tc.policies...)
			bmid.ApplyPolicies(sess)
		}
	}
}

func TestApplyPoliciesQuotaAPILimit(t *testing.T) {
	policiesMu.RLock()
	policy := user.Policy{
		ID:               "two_of_three_with_api_limit",
		Per:              1,
		Rate:             1000,
		QuotaMax:         50,
		QuotaRenewalRate: 3600,
		OrgID:            "default",
		Partitions: user.PolicyPartitions{
			PerAPI:    true,
			Quota:     false,
			RateLimit: false,
			Acl:       false,
		},
		AccessRights: map[string]user.AccessDefinition{
			"api1": {
				Versions: []string{"v1"},
				Limit: &user.APILimit{
					QuotaMax:         100,
					QuotaRenewalRate: 3600,
					Rate:             1000,
					Per:              1,
				},
			},
			"api2": {
				Versions: []string{"v1"},
				Limit: &user.APILimit{
					QuotaMax:         200,
					QuotaRenewalRate: 3600,
					Rate:             1000,
					Per:              1,
				},
			},
			"api3": {
				Versions: []string{"v1"},
			},
		},
	}
	policiesByID = map[string]user.Policy{
		"two_of_three_with_api_limit": policy,
	}
	policiesMu.RUnlock()

	ts := StartTest()
	defer ts.Close()

	// load APIs
	BuildAndLoadAPI(
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
		func(spec *APISpec) {
			spec.Name = "api 3"
			spec.APIID = "api3"
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/api3"
			spec.OrgID = "default"
		},
	)

	// create test session
	session := &user.SessionState{
		ApplyPolicies: []string{"two_of_three_with_api_limit"},
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
	ts.Run(t, []test.TestCase{
		// 2 requests to api1, API limit quota remaining should be 98
		{Method: http.MethodGet, Path: "/api1", Headers: authHeader, Code: http.StatusOK,
			HeadersMatch: map[string]string{XRateLimitRemaining: "99"}},
		{Method: http.MethodGet, Path: "/api1", Headers: authHeader, Code: http.StatusOK,
			HeadersMatch: map[string]string{XRateLimitRemaining: "98"}},
		// 3 requests to api2, API limit quota remaining should be 197
		{Method: http.MethodGet, Path: "/api2", Headers: authHeader, Code: http.StatusOK,
			HeadersMatch: map[string]string{XRateLimitRemaining: "199"}},
		{Method: http.MethodGet, Path: "/api2", Headers: authHeader, Code: http.StatusOK,
			HeadersMatch: map[string]string{XRateLimitRemaining: "198"}},
		{Method: http.MethodGet, Path: "/api2", Headers: authHeader, Code: http.StatusOK,
			HeadersMatch: map[string]string{XRateLimitRemaining: "197"}},
		// 5 requests to api3, API limit quota remaining should be 45
		{Method: http.MethodGet, Path: "/api3", Headers: authHeader, Code: http.StatusOK,
			HeadersMatch: map[string]string{XRateLimitRemaining: "49"}},
		{Method: http.MethodGet, Path: "/api3", Headers: authHeader, Code: http.StatusOK,
			HeadersMatch: map[string]string{XRateLimitRemaining: "48"}},
		{Method: http.MethodGet, Path: "/api3", Headers: authHeader, Code: http.StatusOK,
			HeadersMatch: map[string]string{XRateLimitRemaining: "47"}},
		{Method: http.MethodGet, Path: "/api3", Headers: authHeader, Code: http.StatusOK,
			HeadersMatch: map[string]string{XRateLimitRemaining: "46"}},
		{Method: http.MethodGet, Path: "/api3", Headers: authHeader, Code: http.StatusOK,
			HeadersMatch: map[string]string{XRateLimitRemaining: "45"}},
	}...)

	// check key session
	ts.Run(t, []test.TestCase{
		{
			Method:    http.MethodGet,
			Path:      "/tyk/keys/" + key,
			AdminAuth: true,
			Code:      http.StatusOK,
			BodyMatchFunc: func(data []byte) bool {
				sessionData := user.SessionState{}
				if err := json.Unmarshal(data, &sessionData); err != nil {
					t.Log(err.Error())
					return false
				}
				api1Limit := sessionData.AccessRights["api1"].Limit
				if api1Limit == nil {
					t.Log("api1 limit is not set")
					return false
				}
				api1LimitExpected := user.APILimit{
					Rate:             1000,
					Per:              1,
					QuotaMax:         100,
					QuotaRenewalRate: 3600,
					QuotaRenews:      api1Limit.QuotaRenews,
					QuotaRemaining:   98,
				}
				if !reflect.DeepEqual(*api1Limit, api1LimitExpected) {
					t.Log("api1 limit received:", *api1Limit, "expected:", api1LimitExpected)
					return false
				}
				api2Limit := sessionData.AccessRights["api2"].Limit
				if api2Limit == nil {
					t.Log("api2 limit is not set")
					return false
				}
				api2LimitExpected := user.APILimit{
					Rate:             1000,
					Per:              1,
					QuotaMax:         200,
					QuotaRenewalRate: 3600,
					QuotaRenews:      api2Limit.QuotaRenews,
					QuotaRemaining:   197,
				}
				if !reflect.DeepEqual(*api2Limit, api2LimitExpected) {
					t.Log("api2 limit received:", *api2Limit, "expected:", api2LimitExpected)
					return false
				}
				api3Limit := sessionData.AccessRights["api3"].Limit
				if api3Limit == nil {
					t.Log("api3 limit is not set")
					return false
				}
				api3LimitExpected := user.APILimit{
					Rate:             1000,
					Per:              1,
					QuotaMax:         50,
					QuotaRenewalRate: 3600,
					QuotaRenews:      api3Limit.QuotaRenews,
					QuotaRemaining:   45,
					SetByPolicy:      true,
				}
				if !reflect.DeepEqual(*api3Limit, api3LimitExpected) {
					t.Log("api3 limit received:", *api3Limit, "expected:", api3LimitExpected)
					return false
				}
				return true
			},
		},
	}...)

	// Reset quota
	ts.Run(t, []test.TestCase{
		{
			Method:    http.MethodPut,
			Path:      "/tyk/keys/" + key,
			AdminAuth: true,
			Code:      http.StatusOK,
			Data:      session,
		},
		{
			Method:    http.MethodGet,
			Path:      "/tyk/keys/" + key,
			AdminAuth: true,
			Code:      http.StatusOK,
			BodyMatchFunc: func(data []byte) bool {
				sessionData := user.SessionState{}
				if err := json.Unmarshal(data, &sessionData); err != nil {
					t.Log(err.Error())
					return false
				}
				api1Limit := sessionData.AccessRights["api1"].Limit
				if api1Limit == nil {
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
}

func TestPerAPIPolicyUpdate(t *testing.T) {
	policiesMu.RLock()
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
	policiesByID = map[string]user.Policy{
		"per_api_policy_with_two_apis": policy,
	}
	policiesMu.RUnlock()

	ts := StartTest()
	defer ts.Close()

	// load APIs
	BuildAndLoadAPI(
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
			Path:      "/tyk/keys/" + key,
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
	policiesMu.RLock()
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
	policiesByID = map[string]user.Policy{
		"per_api_policy_with_two_apis": policy,
	}
	policiesMu.RUnlock()

	ts.Run(t, []test.TestCase{
		{
			Method:    http.MethodGet,
			Path:      "/tyk/keys/" + key,
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
