package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jensneuse/graphql-go-tools/pkg/graphql"

	"github.com/lonelycode/go-uuid/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/test"
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
	session   *user.SessionState
}

func testPrepareApplyPolicies() (*BaseMiddleware, []testApplyPoliciesData) {
	policiesMu.RLock()
	policiesByID = map[string]user.Policy{
		"nonpart1": {
			ID:           "p1",
			AccessRights: map[string]user.AccessDefinition{"a": {}},
		},
		"nonpart2": {
			ID:           "p2",
			AccessRights: map[string]user.AccessDefinition{"b": {}},
		},
		"nonpart3": {
			ID:           "p3",
			AccessRights: map[string]user.AccessDefinition{"a": {}, "b": {}},
		},
		"difforg": {OrgID: "different"},
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
		"unlimited-quota": {
			Partitions:   user.PolicyPartitions{Quota: true},
			AccessRights: map[string]user.AccessDefinition{"a": {}},
			QuotaMax:     -1,
		},
		"quota1": {
			Partitions: user.PolicyPartitions{Quota: true},
			QuotaMax:   2,
		},
		"quota2": {
			Partitions: user.PolicyPartitions{Quota: true},
			QuotaMax:   3,
		},
		"quota3": {
			QuotaMax:     3,
			AccessRights: map[string]user.AccessDefinition{"a": {}},
			Partitions:   user.PolicyPartitions{Quota: true},
		},
		"quota4": {
			QuotaMax:     3,
			AccessRights: map[string]user.AccessDefinition{"b": {}},
			Partitions:   user.PolicyPartitions{Quota: true},
		},
		"unlimited-rate": {
			Partitions:   user.PolicyPartitions{RateLimit: true},
			AccessRights: map[string]user.AccessDefinition{"a": {}},
			Rate:         -1,
		},
		"rate1": {
			Partitions: user.PolicyPartitions{RateLimit: true},
			Rate:       3,
		},
		"rate2": {
			Partitions: user.PolicyPartitions{RateLimit: true},
			Rate:       4,
		},
		"rate3": {
			Partitions: user.PolicyPartitions{RateLimit: true},
			Rate:       4,
			Per:        4,
		},
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
		"unlimitedComplexity": {
			Partitions:    user.PolicyPartitions{Complexity: true},
			AccessRights:  map[string]user.AccessDefinition{"a": {}},
			MaxQueryDepth: -1,
		},
		"complexity1": {
			Partitions:    user.PolicyPartitions{Complexity: true},
			MaxQueryDepth: 2,
		},
		"complexity2": {
			Partitions:    user.PolicyPartitions{Complexity: true},
			MaxQueryDepth: 3,
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
				Limit: user.APILimit{
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
				Limit: user.APILimit{
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
					Limit: user.APILimit{
						QuotaMax:         1000,
						QuotaRenewalRate: 3600,
						Rate:             20,
						Per:              1,
					},
				},
				"c": {
					Limit: user.APILimit{
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
					Limit: user.APILimit{
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
					Limit: user.APILimit{
						QuotaMax:         5000,
						QuotaRenewalRate: 3600,
						Rate:             200,
						Per:              10,
					},
				},
				"e": {},
			},
		},
		"per-path1": {
			ID: "per_path_1",
			AccessRights: map[string]user.AccessDefinition{"a": {
				AllowedURLs: []user.AccessSpec{
					{URL: "/user", Methods: []string{"GET"}},
				},
			}, "b": {
				AllowedURLs: []user.AccessSpec{
					{URL: "/", Methods: []string{"PUT"}},
				},
			}},
		},
		"per-path2": {
			ID: "per_path_2",
			AccessRights: map[string]user.AccessDefinition{"a": {
				AllowedURLs: []user.AccessSpec{
					{URL: "/user", Methods: []string{"GET", "POST"}},
					{URL: "/companies", Methods: []string{"GET", "POST"}},
				},
			}},
		},
		"restricted-types1": {
			ID: "restricted_types_1",
			AccessRights: map[string]user.AccessDefinition{
				"a": {
					RestrictedTypes: []graphql.Type{
						{Name: "Country", Fields: []string{"code", "name"}},
						{Name: "Person", Fields: []string{"name", "height"}},
					},
				}},
		},
		"restricted-types2": {
			ID: "restricted_types_2",
			AccessRights: map[string]user.AccessDefinition{
				"a": {
					RestrictedTypes: []graphql.Type{
						{Name: "Country", Fields: []string{"code", "phone"}},
						{Name: "Person", Fields: []string{"name", "mass"}},
					},
				}},
		},
		"field-level-depth-limit1": {
			ID: "field-level-depth-limit1",
			AccessRights: map[string]user.AccessDefinition{
				"graphql-api": {
					Limit: user.APILimit{},
					FieldAccessRights: []user.FieldAccessDefinition{
						{TypeName: "Query", FieldName: "people", Limits: user.FieldLimits{MaxQueryDepth: 4}},
						{TypeName: "Mutation", FieldName: "putPerson", Limits: user.FieldLimits{MaxQueryDepth: 3}},
						{TypeName: "Query", FieldName: "countries", Limits: user.FieldLimits{MaxQueryDepth: 3}},
					},
				}},
		},
		"field-level-depth-limit2": {
			ID: "field-level-depth-limit2",
			AccessRights: map[string]user.AccessDefinition{
				"graphql-api": {
					Limit: user.APILimit{},
					FieldAccessRights: []user.FieldAccessDefinition{
						{TypeName: "Query", FieldName: "people", Limits: user.FieldLimits{MaxQueryDepth: 2}},
						{TypeName: "Mutation", FieldName: "putPerson", Limits: user.FieldLimits{MaxQueryDepth: -1}},
						{TypeName: "Query", FieldName: "continents", Limits: user.FieldLimits{MaxQueryDepth: 4}},
					},
				}},
		},
		"throttle1": {
			ID:                 "throttle1",
			ThrottleRetryLimit: 99,
			ThrottleInterval:   9,
			AccessRights:       map[string]user.AccessDefinition{"a": {}},
		},
	}
	policiesMu.RUnlock()
	bmid := &BaseMiddleware{Spec: &APISpec{
		APIDefinition: &apidef.APIDefinition{},
	}}
	tests := []testApplyPoliciesData{
		{
			"Empty", nil,
			"", nil, nil,
		},
		{
			"Single", []string{"nonpart1"},
			"", nil, nil,
		},
		{
			"Missing", []string{"nonexistent"},
			"not found", nil, nil,
		},
		{
			"DiffOrg", []string{"difforg"},
			"different org", nil, nil,
		},
		{
			name:     "MultiNonPart",
			policies: []string{"nonpart1", "nonpart2"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				want := map[string]user.AccessDefinition{
					"a": {
						Limit:          user.APILimit{},
						AllowanceScope: "p1",
					},
					"b": {
						Limit:          user.APILimit{},
						AllowanceScope: "p2",
					},
				}

				assert.Equal(t, want, s.AccessRights)
			},
		},
		{
			name:     "MultiACLPolicy",
			policies: []string{"nonpart3"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				want := map[string]user.AccessDefinition{
					"a": {
						Limit: user.APILimit{},
					},
					"b": {
						Limit: user.APILimit{},
					},
				}

				assert.Equal(t, want, s.AccessRights)
			},
		},
		{
			"NonpartAndPart", []string{"nonpart1", "quota1"},
			"", nil, nil,
		},
		{
			"TagMerge", []string{"tags1", "tags2"},
			"", func(t *testing.T, s *user.SessionState) {
				want := []string{"key-tag", "tagA", "tagX", "tagY"}
				sort.Strings(s.Tags)

				assert.Equal(t, want, s.Tags)
			}, &user.SessionState{
				Tags: []string{"key-tag"},
			},
		},
		{
			"InactiveMergeOne", []string{"tags1", "inactive1"},
			"", func(t *testing.T, s *user.SessionState) {
				if !s.IsInactive {
					t.Fatalf("want IsInactive to be true")
				}
			}, nil,
		},
		{
			"InactiveMergeAll", []string{"inactive1", "inactive2"},
			"", func(t *testing.T, s *user.SessionState) {
				if !s.IsInactive {
					t.Fatalf("want IsInactive to be true")
				}
			}, nil,
		},
		{
			"InactiveWithSession", []string{"tags1", "tags2"},
			"", func(t *testing.T, s *user.SessionState) {
				if !s.IsInactive {
					t.Fatalf("want IsInactive to be true")
				}
			}, &user.SessionState{
				IsInactive: true,
			},
		},
		{
			"QuotaPart with unlimited", []string{"unlimited-quota"},
			"", func(t *testing.T, s *user.SessionState) {
				if s.QuotaMax != -1 {
					t.Fatalf("want unlimited quota to be -1")
				}
			}, nil,
		},
		{
			"QuotaPart", []string{"quota1"},
			"", func(t *testing.T, s *user.SessionState) {
				if s.QuotaMax != 2 {
					t.Fatalf("want QuotaMax to be 2")
				}
			}, nil,
		},
		{
			"QuotaParts", []string{"quota1", "quota2"},
			"", func(t *testing.T, s *user.SessionState) {
				if s.QuotaMax != 3 {
					t.Fatalf("Should pick bigger value")
				}
			}, nil,
		},
		{
			"QuotaPart with access rights", []string{"quota3"},
			"", func(t *testing.T, s *user.SessionState) {
				if s.QuotaMax != 3 {
					t.Fatalf("quota should be the same as policy quota")
				}
			}, nil,
		},
		{
			"QuotaPart with access rights in multi-policy", []string{"quota4", "nonpart1"},
			"", func(t *testing.T, s *user.SessionState) {
				if s.QuotaMax != 3 {
					t.Fatalf("quota should be the same as policy quota")
				}

				// Don't apply api 'b' coming from quota4 policy
				want := map[string]user.AccessDefinition{"a": {Limit: user.APILimit{}}}
				assert.Equal(t, want, s.AccessRights)
			}, nil,
		},
		{
			"RatePart with unlimited", []string{"unlimited-rate"},
			"", func(t *testing.T, s *user.SessionState) {
				if s.Rate != -1 {
					t.Fatalf("want unlimited rate to be -1")
				}
			}, nil,
		},
		{
			"RatePart", []string{"rate1"},
			"", func(t *testing.T, s *user.SessionState) {
				if s.Rate != 3 {
					t.Fatalf("want Rate to be 3")
				}
			}, nil,
		},
		{
			"RateParts", []string{"rate1", "rate2"},
			"", func(t *testing.T, s *user.SessionState) {
				if s.Rate != 4 {
					t.Fatalf("Should pick bigger value")
				}
			}, nil,
		},
		{
			"ComplexityPart with unlimited", []string{"unlimitedComplexity"},
			"", func(t *testing.T, s *user.SessionState) {
				if s.MaxQueryDepth != -1 {
					t.Fatalf("unlimitied query depth should be -1")
				}
			}, nil,
		},
		{
			"ComplexityPart", []string{"complexity1"},
			"", func(t *testing.T, s *user.SessionState) {
				if s.MaxQueryDepth != 2 {
					t.Fatalf("want MaxQueryDepth to be 2")
				}
			}, nil,
		},
		{
			"ComplexityParts", []string{"complexity1", "complexity2"},
			"", func(t *testing.T, s *user.SessionState) {
				if s.MaxQueryDepth != 3 {
					t.Fatalf("Should pick bigger value")
				}
			}, nil,
		},
		{
			"AclPart", []string{"acl1"},
			"", func(t *testing.T, s *user.SessionState) {
				want := map[string]user.AccessDefinition{"a": {Limit: user.APILimit{}}}

				assert.Equal(t, want, s.AccessRights)
			}, nil,
		},
		{
			"AclPart", []string{"acl1", "acl2"},
			"", func(t *testing.T, s *user.SessionState) {
				want := map[string]user.AccessDefinition{"a": {Limit: user.APILimit{}}, "b": {Limit: user.APILimit{}}}
				assert.Equal(t, want, s.AccessRights)
			}, nil,
		},
		{
			"RightsUpdate", []string{"acl3"},
			"", func(t *testing.T, s *user.SessionState) {
				newPolicy := user.Policy{
					AccessRights: map[string]user.AccessDefinition{"a": {Limit: user.APILimit{}}, "b": {Limit: user.APILimit{}}, "c": {Limit: user.APILimit{}}},
				}
				policiesMu.Lock()
				policiesByID["acl3"] = newPolicy
				policiesMu.Unlock()
				err := bmid.ApplyPolicies(s)
				if err != nil {
					t.Fatalf("couldn't apply policy: %s", err.Error())
				}
				assert.Equal(t, newPolicy.AccessRights, s.AccessRights)
			}, nil,
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
						Limit: user.APILimit{
							QuotaMax:         1000,
							QuotaRenewalRate: 3600,
							Rate:             20,
							Per:              1,
						},
						AllowanceScope: "d",
					},
					"c": {
						Limit: user.APILimit{
							QuotaMax: -1,
							Rate:     2000,
							Per:      60,
						},
						AllowanceScope: "c",
					},
				}

				assert.Equal(t, want, s.AccessRights)
			},
		},
		{
			name:     "several policies with Per API set to true but specifying limit for the same API",
			policies: []string{"per_api_and_no_other_partitions", "per_api_with_the_same_api"},
			errMatch: "cannot apply multiple policies when some have per_api set and some are partitioned",
		},
		{
			name:     "several policies, mixed the one which has Per API set to true and partitioned ones",
			policies: []string{"per_api_and_no_other_partitions", "quota1"},
			errMatch: "",
		},
		{
			name:     "several policies, mixed the one which has Per API set to true and partitioned ones (different order)",
			policies: []string{"rate1", "per_api_and_no_other_partitions"},
			errMatch: "",
		},
		{
			name:     "Per API is set to true and some API gets limit set from policy's fields",
			policies: []string{"per_api_with_limit_set_from_policy"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				want := map[string]user.AccessDefinition{
					"e": {
						Limit: user.APILimit{
							QuotaMax: -1,
							Rate:     300,
							Per:      1,
						},
						AllowanceScope: "per_api_with_limit_set_from_policy",
					},
					"d": {
						Limit: user.APILimit{
							QuotaMax:         5000,
							QuotaRenewalRate: 3600,
							Rate:             200,
							Per:              10,
						},
						AllowanceScope: "d",
					},
				}

				assert.Equal(t, want, s.AccessRights)
			},
		},
		{
			name:     "Merge per path rules for the same API",
			policies: []string{"per-path2", "per-path1"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				want := map[string]user.AccessDefinition{
					"a": {
						AllowedURLs: []user.AccessSpec{
							{URL: "/user", Methods: []string{"GET", "POST", "GET"}},
							{URL: "/companies", Methods: []string{"GET", "POST"}},
						},
						Limit: user.APILimit{},
					},
					"b": {
						AllowedURLs: []user.AccessSpec{
							{URL: "/", Methods: []string{"PUT"}},
						},
						Limit: user.APILimit{},
					},
				}

				assert.Equal(t, want, s.AccessRights)
			},
		},
		{
			name:     "Merge restricted fields for the same GraphQL API",
			policies: []string{"restricted-types1", "restricted-types2"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				want := map[string]user.AccessDefinition{
					"a": { // It should get intersection of restricted types.
						RestrictedTypes: []graphql.Type{
							{Name: "Country", Fields: []string{"code"}},
							{Name: "Person", Fields: []string{"name"}},
						},
						Limit: user.APILimit{},
					},
				}

				assert.Equal(t, want, s.AccessRights)
			},
		},
		{
			name:     "Merge field level depth limit for the same GraphQL API",
			policies: []string{"field-level-depth-limit1", "field-level-depth-limit2"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				want := map[string]user.AccessDefinition{
					"graphql-api": {
						Limit: user.APILimit{},
						FieldAccessRights: []user.FieldAccessDefinition{
							{TypeName: "Query", FieldName: "people", Limits: user.FieldLimits{MaxQueryDepth: 4}},
							{TypeName: "Mutation", FieldName: "putPerson", Limits: user.FieldLimits{MaxQueryDepth: -1}},
							{TypeName: "Query", FieldName: "countries", Limits: user.FieldLimits{MaxQueryDepth: 3}},
							{TypeName: "Query", FieldName: "continents", Limits: user.FieldLimits{MaxQueryDepth: 4}},
						},
					},
				}

				assert.Equal(t, want, s.AccessRights)
			},
		},
		{
			"Throttle interval from policy", []string{"throttle1"},
			"", func(t *testing.T, s *user.SessionState) {
				if s.ThrottleInterval != 9 {
					t.Fatalf("Throttle interval should be 9 inherited from policy")
				}
			}, nil,
		},
		{
			name:     "Throttle retry limit from policy",
			policies: []string{"throttle1"},
			errMatch: "",
			sessMatch: func(t *testing.T, s *user.SessionState) {
				if s.ThrottleRetryLimit != 99 {
					t.Fatalf("Throttle interval should be 9 inherited from policy")
				}
			},
			session: nil,
		},
		{
			name:     "inherit quota and rate from partitioned policies",
			policies: []string{"quota1", "rate3"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				if s.QuotaMax != 2 {
					t.Fatalf("quota should be the same as quota policy")
				}
				if s.Rate != 4 {
					t.Fatalf("rate should be the same as rate policy")
				}
				if s.Per != 4 {
					t.Fatalf("Rate per seconds should be the same as rate policy")
				}
			},
		},
		{
			name:     "inherit quota and rate from partitioned policies applied in different order",
			policies: []string{"rate3", "quota1"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				if s.QuotaMax != 2 {
					t.Fatalf("quota should be the same as quota policy")
				}
				if s.Rate != 4 {
					t.Fatalf("rate should be the same as rate policy")
				}
				if s.Per != 4 {
					t.Fatalf("Rate per seconds should be the same as rate policy")
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
			sess := tc.session
			if sess == nil {
				sess = &user.SessionState{}
			}
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
					Rate:             1000,
					Per:              1,
				},
			},
			"api2": {
				Versions: []string{"v1"},
				Limit: user.APILimit{
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
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "99"}},
			{Method: http.MethodGet, Path: "/api1", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "98"}},
			// 3 requests to api2, API limit quota remaining should be 197
			{Method: http.MethodGet, Path: "/api2", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "199"}},
			{Method: http.MethodGet, Path: "/api2", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "198"}},
			{Method: http.MethodGet, Path: "/api2", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "197"}},
			// 5 requests to api3, API limit quota remaining should be 45
			{Method: http.MethodGet, Path: "/api3", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "49"}},
			{Method: http.MethodGet, Path: "/api3", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "48"}},
			{Method: http.MethodGet, Path: "/api3", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "47"}},
			{Method: http.MethodGet, Path: "/api3", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "46"}},
			{Method: http.MethodGet, Path: "/api3", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "45"}},
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
						Rate:             1000,
						Per:              1,
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
						Rate:             1000,
						Per:              1,
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
						Rate:             1000,
						Per:              1,
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
	policiesMu.RLock()
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

	policiesByID = map[string]user.Policy{
		"policy1": policy1,
		"policy2": policy2,
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
		{Method: http.MethodPost, Path: "/tyk/keys/" + key, Data: session, AdminAuth: true, Code: 200},
	}...)

	// run requests to different APIs
	authHeader := map[string]string{"Authorization": key}

	t.Run("Requests different apis", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			// 2 requests to api1, API limit quota remaining should be 48
			{Path: "/api1", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "49"}},
			{Path: "/api1", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "48"}},

			// 3 requests to api2, API limit quota remaining should be 197
			{Path: "/api2", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "99"}},
			{Path: "/api2", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "98"}},
			{Path: "/api2", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "97"}},

			// 3 requests to api3, should consume policy2 quota, same as for api2
			{Path: "/api3", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "96"}},
			{Path: "/api3", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "95"}},
			{Path: "/api3", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "94"}},
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
						Rate:             1000,
						Per:              1,
						QuotaMax:         50,
						QuotaRenewalRate: 3600,
						QuotaRenews:      sessionData.AccessRights["api1"].Limit.QuotaRenews,
						QuotaRemaining:   48,
					}
					assert.Equal(t, policy1Expected, sessionData.AccessRights["api1"].Limit, "API1 limit do not match")

					policy2Expected := user.APILimit{
						Rate:             100,
						Per:              1,
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
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "49"}},
			{Path: "/api1", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "48"}},
		}...)
	})

	policiesMu.RLock()
	policy1.Rate = 1
	policy1.LastUpdated = strconv.Itoa(int(time.Now().Unix() + 1))
	DRLManager.SetCurrentTokenValue(100)
	defer DRLManager.SetCurrentTokenValue(0)

	policiesByID = map[string]user.Policy{
		"policy1": policy1,
		"policy2": policy2,
	}
	policiesMu.RUnlock()

	// Rate limits after policy update
	t.Run("Rate limits after policy update", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{Path: "/api1", Headers: authHeader, Code: http.StatusOK,
				HeadersMatch: map[string]string{headers.XRateLimitRemaining: "47"}},
			{Path: "/api1", Headers: authHeader, Code: http.StatusTooManyRequests},
		}...)
	})
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
