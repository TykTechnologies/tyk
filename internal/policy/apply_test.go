package policy_test

import (
	"embed"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/tyk/internal/policy"
	"github.com/TykTechnologies/tyk/user"
)

//go:embed testdata/*.json
var testDataFS embed.FS

func TestApplyRateLimits_PolicyLimits(t *testing.T) {
	t.Run("policy limits unset", func(t *testing.T) {
		svc := &policy.Service{}

		session := &user.SessionState{
			Rate: 5,
			Per:  10,
		}
		apiLimits := user.APILimit{
			RateLimit: user.RateLimit{
				Rate: 10,
				Per:  10,
			},
		}
		policy := user.Policy{}

		svc.ApplyRateLimits(session, policy, &apiLimits)

		assert.Equal(t, 10, int(apiLimits.Rate))
		assert.Equal(t, 5, int(session.Rate))
	})

	t.Run("policy limits apply all", func(t *testing.T) {
		svc := &policy.Service{}

		session := &user.SessionState{
			Rate: 5,
			Per:  10,
		}
		apiLimits := user.APILimit{
			RateLimit: user.RateLimit{
				Rate: 5,
				Per:  10,
			},
		}
		policy := user.Policy{
			Rate: 10,
			Per:  10,
		}

		svc.ApplyRateLimits(session, policy, &apiLimits)

		assert.Equal(t, 10, int(apiLimits.Rate))
		assert.Equal(t, 10, int(session.Rate))
	})

	// As the policy defined a higher rate than apiLimits,
	// changes are applied to api limits, but skipped on
	// the session as the session has a higher allowance.
	t.Run("policy limits apply per-api", func(t *testing.T) {
		svc := &policy.Service{}

		session := &user.SessionState{
			Rate: 15,
			Per:  10,
		}
		apiLimits := user.APILimit{
			RateLimit: user.RateLimit{
				Rate: 5,
				Per:  10,
			},
		}
		policy := user.Policy{
			Rate: 10,
			Per:  10,
		}

		svc.ApplyRateLimits(session, policy, &apiLimits)

		assert.Equal(t, 10, int(apiLimits.Rate))
		assert.Equal(t, 15, int(session.Rate))
	})

	// As the policy defined a lower rate than apiLimits,
	// no changes to api limits are applied.
	t.Run("policy limits skip", func(t *testing.T) {
		svc := &policy.Service{}

		session := &user.SessionState{
			Rate: 5,
			Per:  10,
		}
		apiLimits := user.APILimit{
			RateLimit: user.RateLimit{Rate: 15,
				Per: 10,
			},
		}
		policy := user.Policy{
			Rate: 10,
			Per:  10,
		}

		svc.ApplyRateLimits(session, policy, &apiLimits)

		assert.Equal(t, 15, int(apiLimits.Rate))
		assert.Equal(t, 10, int(session.Rate))
	})
}

func TestApplyRateLimits_FromCustomPolicies(t *testing.T) {
	svc := &policy.Service{}

	session := &user.SessionState{}
	session.SetCustomPolicies([]user.Policy{
		{
			ID: "pol1",
			Partitions: user.PolicyPartitions{
				RateLimit: true,
				Acl:       true,
			},
			Rate:         8,
			Per:          1,
			AccessRights: map[string]user.AccessDefinition{"a": {}},
		},
		{
			ID:           "pol2",
			Partitions:   user.PolicyPartitions{RateLimit: true},
			Rate:         10,
			Per:          1,
			AccessRights: map[string]user.AccessDefinition{"a": {}},
		},
	})

	assert.NoError(t, svc.Apply(session))
	assert.Equal(t, 10, int(session.Rate))
}

func TestApplyACL_FromCustomPolicies(t *testing.T) {
	svc := &policy.Service{}

	pol1 := user.Policy{
		ID:         "pol1",
		Partitions: user.PolicyPartitions{RateLimit: true},
		Rate:       8,
		Per:        1,
		AccessRights: map[string]user.AccessDefinition{
			"a": {},
		},
	}

	pol2 := user.Policy{
		ID:         "pol2",
		Partitions: user.PolicyPartitions{Acl: true},
		Rate:       10,
		Per:        1,
		AccessRights: map[string]user.AccessDefinition{
			"a": {
				AllowedURLs: []user.AccessSpec{
					{URL: "/user", Methods: []string{"GET", "POST"}},
					{URL: "/companies", Methods: []string{"GET", "POST"}},
				},
			},
		},
	}

	t.Run("RateLimit first", func(t *testing.T) {
		session := &user.SessionState{}
		session.SetCustomPolicies([]user.Policy{pol1, pol2})

		assert.NoError(t, svc.Apply(session))
		assert.Equal(t, pol2.AccessRights["a"].AllowedURLs, session.AccessRights["a"].AllowedURLs)
		assert.Equal(t, 8, int(session.Rate))
	})

	t.Run("ACL first", func(t *testing.T) {
		session := &user.SessionState{}
		session.SetCustomPolicies([]user.Policy{pol2, pol1})

		assert.NoError(t, svc.Apply(session))
		assert.Equal(t, pol2.AccessRights["a"].AllowedURLs, session.AccessRights["a"].AllowedURLs)
		assert.Equal(t, 8, int(session.Rate))
	})
}

func TestApplyEndpointLevelLimits(t *testing.T) {
	f, err := testDataFS.ReadFile("testdata/apply_endpoint_rl.json")
	assert.NoError(t, err)

	var testCases []struct {
		Name     string         `json:"name"`
		PolicyEP user.Endpoints `json:"policyEP"`
		CurrEP   user.Endpoints `json:"currEP"`
		Expected user.Endpoints `json:"expected"`
	}
	err = json.Unmarshal(f, &testCases)
	assert.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			service := policy.Service{}
			result := service.ApplyEndpointLevelLimits(tc.PolicyEP, tc.CurrEP)
			assert.ElementsMatch(t, tc.Expected, result)
		})
	}

}

type testApplyPoliciesData struct {
	name      string
	policies  []string
	errMatch  string                               // substring
	sessMatch func(*testing.T, *user.SessionState) // ignored if nil
	session   *user.SessionState
	// reverseOrder executes the tests in reversed order of policies,
	// in addition to the order specified in policies
	reverseOrder bool
}

func testPrepareApplyPolicies(tb testing.TB) (*policy.Service, []testApplyPoliciesData) {
	tb.Helper()

	f, err := testDataFS.ReadFile("testdata/policies.json")
	assert.NoError(tb, err)

	var policies = make(map[string]user.Policy)
	err = json.Unmarshal(f, &policies)
	assert.NoError(tb, err)

	var repoPols = make(map[string]user.Policy)
	err = json.Unmarshal(f, &repoPols)
	assert.NoError(tb, err)

	store := policy.NewStoreMap(repoPols)
	orgID := ""
	service := policy.New(&orgID, store, logrus.StandardLogger())

	// splitting tests for readability
	var tests []testApplyPoliciesData

	nilSessionTCs := []testApplyPoliciesData{
		{
			"Empty", nil,
			"", nil, nil, false,
		},
		{
			"Single", []string{"nonpart1"},
			"", nil, nil, false,
		},
		{
			"Missing", []string{"nonexistent"},
			"not found", nil, nil, false,
		},
		{
			"DiffOrg", []string{"difforg"},
			"different org", nil, nil, false,
		},
	}
	tests = append(tests, nilSessionTCs...)

	nonPartitionedTCs := []testApplyPoliciesData{
		{
			name:     "MultiNonPart",
			policies: []string{"nonpart1", "nonpart2", "nonexistent"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				t.Helper()

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
				t.Helper()

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
	}
	tests = append(tests, nonPartitionedTCs...)

	quotaPartitionTCs := []testApplyPoliciesData{
		{
			"QuotaPart with unlimited", []string{"unlimited-quota"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				if s.QuotaMax != -1 {
					t.Fatalf("want unlimited quota to be -1")
				}
			}, nil, false,
		},
		{
			"QuotaPart", []string{"quota1"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				if s.QuotaMax != 2 {
					t.Fatalf("want QuotaMax to be 2")
				}
			}, nil, false,
		},
		{
			"QuotaParts", []string{"quota1", "quota2"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				if s.QuotaMax != 3 {
					t.Fatalf("Should pick bigger value")
				}
			}, nil, false,
		},
		{
			"QuotaParts with acl", []string{"quota5", "quota4"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				assert.Equal(t, int64(4), s.QuotaMax)
			}, nil, false,
		},
		{
			"QuotaPart with access rights", []string{"quota3"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				if s.QuotaMax != 3 {
					t.Fatalf("quota should be the same as policy quota")
				}
			}, nil, false,
		},
		{
			"QuotaPart with access rights in multi-policy", []string{"quota4", "nonpart1"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				if s.QuotaMax != 3 {
					t.Fatalf("quota should be the same as policy quota")
				}

				// Don't apply api 'b' coming from quota4 policy
				want := map[string]user.AccessDefinition{"a": {Limit: user.APILimit{}}}
				assert.Equal(t, want, s.AccessRights)
			}, nil, false,
		},
	}
	tests = append(tests, quotaPartitionTCs...)

	rateLimitPartitionTCs := []testApplyPoliciesData{
		{
			"RatePart with unlimited", []string{"unlimited-rate"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				assert.True(t, s.Rate <= 0, "want unlimited rate to be <= 0")
			}, nil, false,
		},
		{
			"RatePart", []string{"rate1"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				if s.Rate != 3 {
					t.Fatalf("want Rate to be 3")
				}
			}, nil, false,
		},
		{
			"RateParts", []string{"rate1", "rate2"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				if s.Rate != 4 {
					t.Fatalf("Should pick bigger value")
				}
			}, nil, false,
		},
		{
			"RateParts with acl", []string{"rate5", "rate4"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				assert.Equal(t, float64(10), s.Rate)
			}, nil, false,
		},
		{
			"RateParts with acl respected by session", []string{"rate4", "rate5"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				assert.Equal(t, float64(10), s.Rate)
			}, &user.SessionState{Rate: 20}, false,
		},
		{
			"Rate with no partition respected by session", []string{"rate-no-partition"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				assert.Equal(t, float64(12), s.Rate)
			}, &user.SessionState{Rate: 20}, false,
		},
	}
	tests = append(tests, rateLimitPartitionTCs...)

	complexityPartitionTCs := []testApplyPoliciesData{
		{
			"ComplexityPart with unlimited", []string{"unlimitedComplexity"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				if s.MaxQueryDepth != -1 {
					t.Fatalf("unlimitied query depth should be -1")
				}
			}, nil, false,
		},
		{
			"ComplexityPart", []string{"complexity1"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				if s.MaxQueryDepth != 2 {
					t.Fatalf("want MaxQueryDepth to be 2")
				}
			}, nil, false,
		},
		{
			"ComplexityParts", []string{"complexity1", "complexity2"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				if s.MaxQueryDepth != 3 {
					t.Fatalf("Should pick bigger value")
				}
			}, nil, false,
		},
	}
	tests = append(tests, complexityPartitionTCs...)

	aclPartitionTCs := []testApplyPoliciesData{
		{
			"AclPart", []string{"acl1"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				want := map[string]user.AccessDefinition{"a": {Limit: user.APILimit{}}}

				assert.Equal(t, want, s.AccessRights)
			}, nil, false,
		},
		{
			"AclPart", []string{"acl1", "acl2"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				want := map[string]user.AccessDefinition{"a": {Limit: user.APILimit{}}, "b": {Limit: user.APILimit{}}}
				assert.Equal(t, want, s.AccessRights)
			}, nil, false,
		},
		{
			"Acl for a and rate for a,b", []string{"acl1", "rate-for-a-b"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				want := map[string]user.AccessDefinition{"a": {Limit: user.APILimit{RateLimit: user.RateLimit{Rate: 4, Per: 1}}}}
				assert.Equal(t, want, s.AccessRights)
			}, nil, false,
		},
		{
			"Acl for a,b and individual rate for a,b", []string{"acl-for-a-b", "rate-for-a", "rate-for-b"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				want := map[string]user.AccessDefinition{
					"a": {Limit: user.APILimit{RateLimit: user.RateLimit{Rate: 4, Per: 1}}},
					"b": {Limit: user.APILimit{RateLimit: user.RateLimit{Rate: 2, Per: 1}}},
				}
				assert.Equal(t, want, s.AccessRights)
			}, nil, false,
		},
		{
			"RightsUpdate", []string{"acl-for-a-b"},
			"", func(t *testing.T, ses *user.SessionState) {
				t.Helper()
				expectedAccessRights := map[string]user.AccessDefinition{"a": {Limit: user.APILimit{}}, "b": {Limit: user.APILimit{}}}
				assert.Equal(t, expectedAccessRights, ses.AccessRights)
			}, &user.SessionState{
				AccessRights: map[string]user.AccessDefinition{
					"c": {Limit: user.APILimit{}},
				},
			}, false,
		},
	}
	tests = append(tests, aclPartitionTCs...)

	inactiveTCs := []testApplyPoliciesData{
		{
			"InactiveMergeOne", []string{"tags1", "inactive1"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				if !s.IsInactive {
					t.Fatalf("want IsInactive to be true")
				}
			}, nil, false,
		},
		{
			"InactiveMergeAll", []string{"inactive1", "inactive2"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				if !s.IsInactive {
					t.Fatalf("want IsInactive to be true")
				}
			}, nil, false,
		},
		{
			"InactiveWithSession", []string{"tags1", "tags2"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				if !s.IsInactive {
					t.Fatalf("want IsInactive to be true")
				}
			}, &user.SessionState{
				IsInactive: true,
			}, false,
		},
	}
	tests = append(tests, inactiveTCs...)

	perAPITCs := []testApplyPoliciesData{
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
				t.Helper()

				want := map[string]user.AccessDefinition{
					"c": {
						Limit: user.APILimit{
							RateLimit: user.RateLimit{
								Rate: 2000,
								Per:  60,
							},
							QuotaMax: -1,
						},
						AllowanceScope: "c",
					},
					"d": {
						Limit: user.APILimit{
							RateLimit: user.RateLimit{
								Rate: 20,
								Per:  1,
							},
							QuotaMax:         1000,
							QuotaRenewalRate: 3600,
						},
						AllowanceScope: "d",
					},
				}
				assert.Equal(t, want, s.AccessRights)
			},
		},
		{
			name:     "several policies with Per API set to true specifying limit for the same API",
			policies: []string{"per_api_and_no_other_partitions", "per_api_with_api_d"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				t.Helper()
				want := map[string]user.AccessDefinition{
					"c": {
						Limit: user.APILimit{
							RateLimit: user.RateLimit{
								Rate: 2000,
								Per:  60,
							},
							QuotaMax: -1,
						},
						AllowanceScope: "c",
					},
					"d": {
						Limit: user.APILimit{
							RateLimit: user.RateLimit{
								Rate: 200,
								Per:  10,
							},
							QuotaMax:         5000,
							QuotaRenewalRate: 3600,
						},
						AllowanceScope: "d",
					},
				}
				assert.Equal(t, want, s.AccessRights)
			},
		},
		{
			name:     "several policies with Per API set to true specifying limit for the same APIs",
			policies: []string{"per_api_and_no_other_partitions", "per_api_with_api_d", "per_api_with_api_c"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				t.Helper()
				want := map[string]user.AccessDefinition{
					"c": {
						Limit: user.APILimit{
							RateLimit: user.RateLimit{
								Rate: 3000,
								Per:  10,
							},
							QuotaMax: -1,
						},
						AllowanceScope: "c",
					},
					"d": {
						Limit: user.APILimit{
							RateLimit: user.RateLimit{
								Rate: 200,
								Per:  10,
							},
							QuotaMax:         5000,
							QuotaRenewalRate: 3600,
						},
						AllowanceScope: "d",
					},
				}
				assert.Equal(t, want, s.AccessRights)
			},
		},
		{
			name:     "several policies, mixed the one which has Per API set to true and partitioned ones",
			policies: []string{"per_api_with_api_d", "quota1"},
			errMatch: "cannot apply multiple policies when some have per_api set and some are partitioned",
		},
		{
			name:     "several policies, mixed the one which has Per API set to true and partitioned ones (different order)",
			policies: []string{"rate1", "per_api_with_api_d"},
			errMatch: "cannot apply multiple policies when some have per_api set and some are partitioned",
		},
		{
			name:     "Per API is set to true and some API gets limit set from policy's fields",
			policies: []string{"per_api_with_limit_set_from_policy"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				t.Helper()
				want := map[string]user.AccessDefinition{
					"e": {
						Limit: user.APILimit{
							QuotaMax: -1,
							RateLimit: user.RateLimit{
								Rate: 300,
								Per:  1,
							},
						},
						AllowanceScope: "per_api_with_limit_set_from_policy",
					},
					"d": {
						Limit: user.APILimit{
							QuotaMax:         5000,
							QuotaRenewalRate: 3600,
							RateLimit: user.RateLimit{
								Rate: 200,
								Per:  10,
							},
						},
						AllowanceScope: "d",
					},
				}
				assert.Equal(t, want, s.AccessRights)
			},
		},
		{
			name: "Per API with limits override",
			policies: []string{
				"per_api_with_limit_set_from_policy",
				"per_api_with_api_d",
				"per_api_with_higher_rate_on_api_d",
			},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				t.Helper()
				want := map[string]user.AccessDefinition{
					"e": {
						Limit: user.APILimit{
							QuotaMax: -1,
							RateLimit: user.RateLimit{
								Rate: 300,
								Per:  1,
							},
						},
						AllowanceScope: "per_api_with_limit_set_from_policy",
					},
					"d": {
						Limit: user.APILimit{
							QuotaMax:         5000,
							QuotaRenewalRate: 3600,
							RateLimit: user.RateLimit{
								Rate: 200,
								Per:  10,
							},
						},
						AllowanceScope: "d",
					},
				}
				assert.Equal(t, want, s.AccessRights)
			},
		},
	}
	tests = append(tests, perAPITCs...)

	graphQLTCs := []testApplyPoliciesData{
		{
			name:     "Merge per path rules for the same API",
			policies: []string{"per-path2", "per-path1"},
			sessMatch: func(t *testing.T, sess *user.SessionState) {
				t.Helper()
				want := map[string]user.AccessDefinition{
					"a": {
						AllowedURLs: []user.AccessSpec{
							{URL: "/user", Methods: []string{"GET", "POST"}},
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

				gotPolicy, ok := store.PolicyByID("per-path2")

				assert.True(t, ok)
				assert.Equal(t, user.AccessSpec{
					URL: "/user", Methods: []string{"GET"},
				}, gotPolicy.AccessRights["a"].AllowedURLs[0])

				assert.Equal(t, want, sess.AccessRights)
			},
		},
		{
			name:     "Merge restricted fields for the same GraphQL API",
			policies: []string{"restricted-types1", "restricted-types2"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				t.Helper()

				want := map[string]user.AccessDefinition{
					"a": {
						RestrictedTypes: []graphql.Type{
							{Name: "Country", Fields: []string{"code", "name", "phone"}},
							{Name: "Person", Fields: []string{"name", "height", "mass"}},
						},
						Limit: user.APILimit{},
					},
				}

				assert.Equal(t, want, s.AccessRights)
			},
		},
		{
			name:     "Merge allowed fields for the same GraphQL API",
			policies: []string{"allowed-types1", "allowed-types2"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				t.Helper()

				want := map[string]user.AccessDefinition{
					"a": {
						AllowedTypes: []graphql.Type{
							{Name: "Country", Fields: []string{"code", "name", "phone"}},
							{Name: "Person", Fields: []string{"name", "height", "mass"}},
						},
						RestrictedTypes: []graphql.Type{
							{Name: "Dog", Fields: []string{"name", "breed", "country"}},
							{Name: "Cat", Fields: []string{"name", "country"}},
						},
						Limit: user.APILimit{},
					},
				}

				assert.Equal(t, want, s.AccessRights)
			},
		},
		{
			name:     "If GQL introspection is disabled, it remains disabled after merging",
			policies: []string{"introspection-disabled", "introspection-enabled"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				t.Helper()

				want := map[string]user.AccessDefinition{
					"a": {
						DisableIntrospection: true, // If GQL introspection is disabled, it remains disabled after merging.
						Limit:                user.APILimit{},
					},
				}

				assert.Equal(t, want, s.AccessRights)
			},
		},
		{
			name:     "Merge field level depth limit for the same GraphQL API",
			policies: []string{"field-level-depth-limit1", "field-level-depth-limit2"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				t.Helper()

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
	}
	tests = append(tests, graphQLTCs...)

	throttleTCs := []testApplyPoliciesData{
		{
			"Throttle interval from policy", []string{"throttle1"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				if s.ThrottleInterval != 9 {
					t.Fatalf("Throttle interval should be 9 inherited from policy")
				}
			}, nil, false,
		},
		{
			name:     "Throttle retry limit from policy",
			policies: []string{"throttle1"},
			errMatch: "",
			sessMatch: func(t *testing.T, s *user.SessionState) {
				t.Helper()

				if s.ThrottleRetryLimit != 99 {
					t.Fatalf("Throttle interval should be 9 inherited from policy")
				}
			},
			session: nil,
		},
	}
	tests = append(tests, throttleTCs...)

	tagsTCs := []testApplyPoliciesData{
		{
			"TagMerge", []string{"tags1", "tags2"},
			"", func(t *testing.T, s *user.SessionState) {
				t.Helper()
				want := []string{"key-tag", "tagA", "tagX", "tagY"}
				sort.Strings(s.Tags)

				assert.Equal(t, want, s.Tags)
			}, &user.SessionState{
				Tags: []string{"key-tag"},
			}, false,
		},
	}
	tests = append(tests, tagsTCs...)

	partitionTCs := []testApplyPoliciesData{
		{
			"NonpartAndPart", []string{"nonpart1", "quota1"},
			"", nil, nil, false,
		},
		{
			name:     "inherit quota and rate from partitioned policies",
			policies: []string{"quota1", "rate3"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				t.Helper()

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
				t.Helper()

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
	tests = append(tests, partitionTCs...)

	endpointRLTCs := []testApplyPoliciesData{
		{
			name:     "Per API and per endpoint policies",
			policies: []string{"per_api_with_limit_set_from_policy", "per_api_with_endpoint_limits_on_d_and_e"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				t.Helper()
				endpointsConfig := user.Endpoints{
					{
						Path: "/get",
						Methods: user.EndpointMethods{
							{
								Name: "GET",
								Limit: user.RateLimit{
									Rate: -1,
								},
							},
						},
					},
					{
						Path: "/post",
						Methods: user.EndpointMethods{
							{
								Name: "POST",
								Limit: user.RateLimit{
									Rate: 300,
									Per:  10,
								},
							},
						},
					},
				}
				want := map[string]user.AccessDefinition{
					"e": {
						Limit: user.APILimit{
							QuotaMax: -1,
							RateLimit: user.RateLimit{
								Rate: 500,
								Per:  1,
							},
						},
						AllowanceScope: "per_api_with_endpoint_limits_on_d_and_e",
						Endpoints:      endpointsConfig,
					},
					"d": {
						Limit: user.APILimit{
							QuotaMax:         5000,
							QuotaRenewalRate: 3600,
							RateLimit: user.RateLimit{
								Rate: 200,
								Per:  10,
							},
						},
						AllowanceScope: "d",
						Endpoints:      endpointsConfig,
					},
				}
				assert.Equal(t, want, s.AccessRights)
			},
			reverseOrder: true,
		},
		{
			name: "Endpoint level limits overlapping",
			policies: []string{
				"per_api_with_limit_set_from_policy",
				"per_api_with_endpoint_limits_on_d_and_e",
				"per_endpoint_limits_different_on_api_d",
			},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				t.Helper()
				apiEEndpoints := user.Endpoints{
					{
						Path: "/get",
						Methods: user.EndpointMethods{
							{
								Name: "GET",
								Limit: user.RateLimit{
									Rate: -1,
								},
							},
						},
					},
					{
						Path: "/post",
						Methods: user.EndpointMethods{
							{
								Name: "POST",
								Limit: user.RateLimit{
									Rate: 300,
									Per:  10,
								},
							},
						},
					},
				}

				assert.ElementsMatch(t, apiEEndpoints, s.AccessRights["e"].Endpoints)

				apiDEndpoints := user.Endpoints{
					{
						Path: "/get",
						Methods: user.EndpointMethods{
							{
								Name: "GET",
								Limit: user.RateLimit{
									Rate: -1,
								},
							},
						},
					},
					{
						Path: "/post",
						Methods: user.EndpointMethods{
							{
								Name: "POST",
								Limit: user.RateLimit{
									Rate: 400,
									Per:  11,
								},
							},
						},
					},
					{
						Path: "/anything",
						Methods: user.EndpointMethods{
							{
								Name: "PUT",
								Limit: user.RateLimit{
									Rate: 500,
									Per:  10,
								},
							},
						},
					},
				}

				assert.ElementsMatch(t, apiDEndpoints, s.AccessRights["d"].Endpoints)

				apiELimits := user.APILimit{
					QuotaMax: -1,
					RateLimit: user.RateLimit{
						Rate: 500,
						Per:  1,
					},
				}
				assert.Equal(t, apiELimits, s.AccessRights["e"].Limit)

				apiDLimits := user.APILimit{
					QuotaMax:         5000,
					QuotaRenewalRate: 3600,
					RateLimit: user.RateLimit{
						Rate: 200,
						Per:  10,
					},
				}
				assert.Equal(t, apiDLimits, s.AccessRights["d"].Limit)
			},
			reverseOrder: true,
		},
		{
			name:     "endpoint_rate_limits_on_acl_partition_only",
			policies: []string{"endpoint_rate_limits_on_acl_partition_only"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				t.Helper()
				assert.NotEmpty(t, s.AccessRights)
				assert.Empty(t, s.AccessRights["d"].Endpoints)
			},
		},
		{
			name: "endpoint_rate_limits_when_acl_and_quota_partitions_combined",
			policies: []string{
				"endpoint_rate_limits_on_acl_partition_only",
				"endpoint_rate_limits_on_quota_partition_only",
			},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				t.Helper()
				assert.NotEmpty(t, s.AccessRights)
				assert.Empty(t, s.AccessRights["d"].Endpoints)
			},
			reverseOrder: true,
		},
	}

	tests = append(tests, endpointRLTCs...)

	combinedEndpointRLTCs := []testApplyPoliciesData{
		{
			name: "combine_non_partitioned_policies_with_endpoint_rate_limits_configured_on_api_d",
			policies: []string{
				"api_d_get_endpoint_rl_1_configure_on_non_partitioned_policy",
				"api_d_get_endpoint_rl_2_configure_on_non_partitioned_policy",
			},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				t.Helper()
				assert.NotEmpty(t, s.AccessRights)
				apiDEndpoints := user.Endpoints{
					{
						Path: "/get",
						Methods: user.EndpointMethods{
							{
								Name: "GET",
								Limit: user.RateLimit{
									Rate: 20,
									Per:  60,
								},
							},
						},
					},
				}

				assert.ElementsMatch(t, apiDEndpoints, s.AccessRights["d"].Endpoints)
			},
			reverseOrder: true,
		},
		{
			name: "combine_non_partitioned_policies_with_endpoint_rate_limits_no_bound_configured_on_api_d",
			policies: []string{
				"api_d_get_endpoint_rl_1_configure_on_non_partitioned_policy",
				"api_d_get_endpoint_rl_2_configure_on_non_partitioned_policy",
				"api_d_get_endpoint_rl_3_configure_on_non_partitioned_policy",
			},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				t.Helper()
				assert.NotEmpty(t, s.AccessRights)
				apiDEndpoints := user.Endpoints{
					{
						Path: "/get",
						Methods: user.EndpointMethods{
							{
								Name: "GET",
								Limit: user.RateLimit{
									Rate: -1,
								},
							},
						},
					},
				}

				assert.ElementsMatch(t, apiDEndpoints, s.AccessRights["d"].Endpoints)
			},
			reverseOrder: true,
		},
		{
			name: "combine_non_partitioned_policies_with_multiple_endpoint_rate_limits_configured_on_api_d",
			policies: []string{
				"api_d_get_endpoint_rl_1_configure_on_non_partitioned_policy",
				"api_d_get_endpoint_rl_2_configure_on_non_partitioned_policy",
				"api_d_get_endpoint_rl_3_configure_on_non_partitioned_policy",
				"api_d_post_endpoint_rl_1_configure_on_non_partitioned_policy",
			},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				t.Helper()
				assert.NotEmpty(t, s.AccessRights)
				apiDEndpoints := user.Endpoints{
					{
						Path: "/get",
						Methods: user.EndpointMethods{
							{
								Name: "GET",
								Limit: user.RateLimit{
									Rate: -1,
								},
							},
						},
					},
					{
						Path: "/post",
						Methods: user.EndpointMethods{
							{
								Name: "POST",
								Limit: user.RateLimit{
									Rate: 20,
									Per:  60,
								},
							},
						},
					},
				}

				assert.ElementsMatch(t, apiDEndpoints, s.AccessRights["d"].Endpoints)
			},
			reverseOrder: true,
		},
		{
			name: "combine_non_partitioned_policies_with_endpoint_rate_limits_configured_on_api_d_and_e",
			policies: []string{
				"api_d_get_endpoint_rl_1_configure_on_non_partitioned_policy",
				"api_d_get_endpoint_rl_2_configure_on_non_partitioned_policy",
				"api_d_get_endpoint_rl_3_configure_on_non_partitioned_policy",
				"api_d_post_endpoint_rl_1_configure_on_non_partitioned_policy",
				"api_e_get_endpoint_rl_1_configure_on_non_partitioned_policy",
			},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				t.Helper()
				assert.NotEmpty(t, s.AccessRights)
				apiDEndpoints := user.Endpoints{
					{
						Path: "/get",
						Methods: user.EndpointMethods{
							{
								Name: "GET",
								Limit: user.RateLimit{
									Rate: -1,
								},
							},
						},
					},
					{
						Path: "/post",
						Methods: user.EndpointMethods{
							{
								Name: "POST",
								Limit: user.RateLimit{
									Rate: 20,
									Per:  60,
								},
							},
						},
					},
				}

				assert.ElementsMatch(t, apiDEndpoints, s.AccessRights["d"].Endpoints)

				apiEEndpoints := user.Endpoints{
					{
						Path: "/get",
						Methods: user.EndpointMethods{
							{
								Name: "GET",
								Limit: user.RateLimit{
									Rate: 100,
									Per:  60,
								},
							},
						},
					},
				}

				assert.ElementsMatch(t, apiEEndpoints, s.AccessRights["e"].Endpoints)
			},
			reverseOrder: true,
		},
	}

	tests = append(tests, combinedEndpointRLTCs...)

	return service, tests
}

func TestService_Apply(t *testing.T) {
	service, tests := testPrepareApplyPolicies(t)

	for _, tc := range tests {
		pols := [][]string{tc.policies}
		if tc.reverseOrder {
			var copyPols = make([]string, len(tc.policies))
			copy(copyPols, tc.policies)
			slices.Reverse(copyPols)
			pols = append(pols, copyPols)
		}

		for i, policies := range pols {
			name := tc.name
			if i == 1 {
				name = fmt.Sprintf("%s, reversed=%t", name, true)
			}

			t.Run(name, func(t *testing.T) {
				sess := tc.session
				if sess == nil {
					sess = &user.SessionState{}
				}
				sess.SetPolicies(policies...)
				if err := service.Apply(sess); err != nil {
					assert.ErrorContains(t, err, tc.errMatch)
					return
				}

				if tc.sessMatch != nil {
					tc.sessMatch(t, sess)
				}
			})
		}
	}
}

func BenchmarkService_Apply(b *testing.B) {
	b.ReportAllocs()

	service, tests := testPrepareApplyPolicies(b)

	for i := 0; i < b.N; i++ {
		for _, tc := range tests {
			sess := &user.SessionState{}
			sess.SetPolicies(tc.policies...)
			err := service.Apply(sess)
			assert.NoError(b, err)
		}
	}
}
