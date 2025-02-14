package gateway

import (
	"embed"
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

	persistentmodel "github.com/TykTechnologies/storage/persistent/model"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/rpc"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"

	"github.com/TykTechnologies/tyk/internal/uuid"
)

//go:embed testdata/*.json
var testDataFS embed.FS

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

type testApplyPoliciesData struct {
	name      string
	policies  []string
	errMatch  string                               // substring
	sessMatch func(*testing.T, *user.SessionState) // ignored if nil
	session   *user.SessionState
}

func (s *Test) testPrepareApplyPolicies(tb testing.TB) (*BaseMiddleware, []testApplyPoliciesData) {
	tb.Helper()

	f, err := testDataFS.ReadFile("testdata/policies.json")
	assert.NoError(tb, err)

	var policies = make(map[string]user.Policy)
	err = json.Unmarshal(f, &policies)
	assert.NoError(tb, err)

	s.Gw.policiesMu.RLock()
	s.Gw.policiesByID = policies
	s.Gw.policiesMu.RUnlock()

	bmid := &BaseMiddleware{
		Spec: &APISpec{
			APIDefinition: &apidef.APIDefinition{},
		},
		Gw: s.Gw,
	}
	// splitting tests for readability
	var tests []testApplyPoliciesData

	nilSessionTCs := []testApplyPoliciesData{
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
			"QuotaParts with acl", []string{"quota5", "quota4"},
			"", func(t *testing.T, s *user.SessionState) {
				assert.Equal(t, int64(4), s.QuotaMax)
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
	}
	tests = append(tests, quotaPartitionTCs...)

	rateLimitPartitionTCs := []testApplyPoliciesData{
		{
			"RatePart with unlimited", []string{"unlimited-rate"},
			"", func(t *testing.T, s *user.SessionState) {
				assert.True(t, s.Rate <= 0, "want unlimited rate to be <= 0")
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
			"RateParts with acl", []string{"rate5", "rate4"},
			"", func(t *testing.T, s *user.SessionState) {
				assert.Equal(t, float64(10), s.Rate)
			}, nil,
		},
		{
			"RateParts with acl respected by session", []string{"rate4", "rate5"},
			"", func(t *testing.T, s *user.SessionState) {
				assert.Equal(t, float64(10), s.Rate)
			}, &user.SessionState{Rate: 20},
		},
		{
			"Rate with no partition respected by session", []string{"rate-no-partition"},
			"", func(t *testing.T, s *user.SessionState) {
				assert.Equal(t, float64(12), s.Rate)
			}, &user.SessionState{Rate: 20},
		},
	}
	tests = append(tests, rateLimitPartitionTCs...)

	complexityPartitionTCs := []testApplyPoliciesData{
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
	}
	tests = append(tests, complexityPartitionTCs...)

	aclPartitionTCs := []testApplyPoliciesData{
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
			"Acl for a and rate for a,b", []string{"acl1", "rate-for-a-b"},
			"", func(t *testing.T, s *user.SessionState) {
				want := map[string]user.AccessDefinition{"a": {Limit: user.APILimit{RateLimit: user.RateLimit{Rate: 4, Per: 1}}}}
				assert.Equal(t, want, s.AccessRights)
			}, nil,
		},
		{
			"Acl for a,b and individual rate for a,b", []string{"acl-for-a-b", "rate-for-a", "rate-for-b"},
			"", func(t *testing.T, s *user.SessionState) {
				want := map[string]user.AccessDefinition{
					"a": {Limit: user.APILimit{RateLimit: user.RateLimit{Rate: 4, Per: 1}}},
					"b": {Limit: user.APILimit{RateLimit: user.RateLimit{Rate: 2, Per: 1}}},
				}
				assert.Equal(t, want, s.AccessRights)
			}, nil,
		},
		{
			"RightsUpdate", []string{"acl3"},
			"", func(t *testing.T, ses *user.SessionState) {
				newPolicy := user.Policy{
					AccessRights: map[string]user.AccessDefinition{"a": {Limit: user.APILimit{}}, "b": {Limit: user.APILimit{}}, "c": {Limit: user.APILimit{}}},
				}

				s.Gw.policiesMu.Lock()
				s.Gw.policiesByID["acl3"] = newPolicy
				s.Gw.policiesMu.Unlock()
				err := bmid.ApplyPolicies(ses)
				if err != nil {
					t.Fatalf("couldn't apply policy: %s", err.Error())
				}
				assert.Equal(t, newPolicy.AccessRights, ses.AccessRights)
			}, nil,
		},
	}
	tests = append(tests, aclPartitionTCs...)

	inactiveTCs := []testApplyPoliciesData{
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

				gotPolicy, ok := s.Gw.PolicyByID("per-path2")

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
			name:     "Merge allowed fields for the same GraphQL API",
			policies: []string{"allowed-types1", "allowed-types2"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
				t.Helper()

				want := map[string]user.AccessDefinition{
					"a": { // It should get intersection of restricted types.
						AllowedTypes: []graphql.Type{
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
				want := []string{"key-tag", "tagA", "tagX", "tagY"}
				sort.Strings(s.Tags)

				assert.Equal(t, want, s.Tags)
			}, &user.SessionState{
				Tags: []string{"key-tag"},
			},
		},
	}
	tests = append(tests, tagsTCs...)

	partitionTCs := []testApplyPoliciesData{
		{
			"NonpartAndPart", []string{"nonpart1", "quota1"},
			"", nil, nil,
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
		},
	}

	tests = append(tests, endpointRLTCs...)

	return bmid, tests
}

func TestApplyPolicies(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	bmid, tests := ts.testPrepareApplyPolicies(t)

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
	ts := StartTest(nil)
	defer ts.Close()

	bmid, tests := ts.testPrepareApplyPolicies(b)

	for i := 0; i < b.N; i++ {
		for _, tc := range tests {
			sess := &user.SessionState{}
			sess.SetPolicies(tc.policies...)
			bmid.ApplyPolicies(sess)
		}
	}
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
