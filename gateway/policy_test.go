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

func TestLoadPoliciesFromDashboardReLogin(t *testing.T) {
	// Test Dashboard
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

func (s *Test) TestPrepareApplyPolicies() (*BaseMiddleware, []testApplyPoliciesData) {
	s.Gw.policiesMu.RLock()
	s.Gw.policiesByID = map[string]user.Policy{
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
			Partitions:   user.PolicyPartitions{Quota: true, Acl: true},
			Tags:         []string{"tagA"},
			AccessRights: map[string]user.AccessDefinition{"a": {}},
		},
		"tags2": {
			Partitions:   user.PolicyPartitions{RateLimit: true, Acl: true},
			Tags:         []string{"tagX", "tagY"},
			AccessRights: map[string]user.AccessDefinition{"b": {}},
		},
		"inactive1": {
			Partitions:   user.PolicyPartitions{RateLimit: true, Acl: true},
			IsInactive:   true,
			AccessRights: map[string]user.AccessDefinition{"a": {}},
		},
		"inactive2": {
			Partitions:   user.PolicyPartitions{Quota: true, Acl: true},
			IsInactive:   true,
			AccessRights: map[string]user.AccessDefinition{"b": {}},
		},
		"unlimited-quota": {
			Partitions:   user.PolicyPartitions{Quota: true, Acl: true},
			AccessRights: map[string]user.AccessDefinition{"a": {}},
			QuotaMax:     -1,
		},
		"quota1": {
			Partitions:   user.PolicyPartitions{Quota: true, Acl: true},
			QuotaMax:     2,
			AccessRights: map[string]user.AccessDefinition{"a": {}},
		},
		"quota2": {
			Partitions:   user.PolicyPartitions{Quota: true, Acl: true},
			QuotaMax:     3,
			AccessRights: map[string]user.AccessDefinition{"b": {}},
		},
		"quota3": {
			QuotaMax:     3,
			AccessRights: map[string]user.AccessDefinition{"a": {}},
			Partitions:   user.PolicyPartitions{Quota: true, Acl: true},
		},
		"quota4": {
			QuotaMax:     3,
			AccessRights: map[string]user.AccessDefinition{"b": {}},
			Partitions:   user.PolicyPartitions{Quota: true},
		},
		"quota5": {
			QuotaMax:     4,
			Partitions:   user.PolicyPartitions{Quota: true, Acl: true},
			AccessRights: map[string]user.AccessDefinition{"b": {}},
		},
		"unlimited-rate": {
			Partitions:   user.PolicyPartitions{RateLimit: true, Acl: true},
			AccessRights: map[string]user.AccessDefinition{"a": {}},
			Rate:         -1,
		},
		"rate1": {
			Partitions:   user.PolicyPartitions{RateLimit: true, Acl: true},
			AccessRights: map[string]user.AccessDefinition{"a": {}},
			Rate:         3,
		},
		"rate2": {
			Partitions:   user.PolicyPartitions{RateLimit: true, Acl: true},
			AccessRights: map[string]user.AccessDefinition{"b": {}},
			Rate:         4,
		},
		"rate3": {
			Partitions:   user.PolicyPartitions{RateLimit: true, Acl: true},
			Rate:         4,
			Per:          4,
			AccessRights: map[string]user.AccessDefinition{"a": {}},
		},
		"rate4": {
			Partitions:   user.PolicyPartitions{RateLimit: true, Acl: true},
			Rate:         8,
			AccessRights: map[string]user.AccessDefinition{"a": {}},
		},
		"rate5": {
			Partitions:   user.PolicyPartitions{RateLimit: true, Acl: true},
			Rate:         10,
			AccessRights: map[string]user.AccessDefinition{"a": {}},
		},
		"rate-for-a": {
			Partitions:   user.PolicyPartitions{RateLimit: true, Acl: true},
			AccessRights: map[string]user.AccessDefinition{"a": {}},
			Rate:         4,
		},
		"rate-for-b": {
			Partitions:   user.PolicyPartitions{RateLimit: true, Acl: true},
			AccessRights: map[string]user.AccessDefinition{"b": {}},
			Rate:         2,
		},
		"rate-for-a-b": {
			Partitions:   user.PolicyPartitions{RateLimit: true, Acl: true},
			AccessRights: map[string]user.AccessDefinition{"a": {}, "b": {}},
			Rate:         4,
		},
		"rate-no-partition": {
			AccessRights: map[string]user.AccessDefinition{"a": {}},
			Rate:         12,
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
		"acl-for-a-b": {
			Partitions:   user.PolicyPartitions{Acl: true},
			AccessRights: map[string]user.AccessDefinition{"a": {}, "b": {}},
		},
		"unlimitedComplexity": {
			Partitions:    user.PolicyPartitions{Complexity: true, Acl: true},
			AccessRights:  map[string]user.AccessDefinition{"a": {}},
			MaxQueryDepth: -1,
		},
		"complexity1": {
			Partitions:    user.PolicyPartitions{Complexity: true, Acl: true},
			AccessRights:  map[string]user.AccessDefinition{"a": {}},
			MaxQueryDepth: 2,
		},
		"complexity2": {
			Partitions:    user.PolicyPartitions{Complexity: true, Acl: true},
			AccessRights:  map[string]user.AccessDefinition{"b": {}},
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
					{URL: "/user", Methods: []string{"GET", "POST"}},
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
					{URL: "/user", Methods: []string{"GET"}},
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
		"allowed-types1": {
			ID: "allowed_types_1",
			AccessRights: map[string]user.AccessDefinition{
				"a": {
					AllowedTypes: []graphql.Type{
						{Name: "Country", Fields: []string{"code", "name"}},
						{Name: "Person", Fields: []string{"name", "height"}},
					},
				}},
		},
		"allowed-types2": {
			ID: "allowed_types_2",
			AccessRights: map[string]user.AccessDefinition{
				"a": {
					AllowedTypes: []graphql.Type{
						{Name: "Country", Fields: []string{"code", "phone"}},
						{Name: "Person", Fields: []string{"name", "mass"}},
					},
				}},
		},
		"introspection-disabled": {
			ID: "introspection_disabled",
			AccessRights: map[string]user.AccessDefinition{
				"a": {
					DisableIntrospection: true,
				}},
		},
		"introspection-enabled": {
			ID: "introspection_enabled",
			AccessRights: map[string]user.AccessDefinition{
				"a": {
					DisableIntrospection: false,
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
	s.Gw.policiesMu.RUnlock()
	bmid := &BaseMiddleware{
		Spec: &APISpec{
			APIDefinition: &apidef.APIDefinition{},
		},
		Gw: s.Gw,
	}
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
			policies: []string{"nonpart1", "nonpart2", "nonexistent"},
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
			"Acl for a and rate for a,b", []string{"acl1", "rate-for-a-b"},
			"", func(t *testing.T, s *user.SessionState) {
				want := map[string]user.AccessDefinition{"a": {Limit: user.APILimit{Rate: 4}}, "b": {Limit: user.APILimit{Rate: 4}}}
				assert.Equal(t, want, s.AccessRights)
			}, nil,
		},
		{
			"Acl for a,b and individual rate for a,b", []string{"acl-for-a-b", "rate-for-a", "rate-for-b"},
			"", func(t *testing.T, s *user.SessionState) {
				want := map[string]user.AccessDefinition{
					"a": {Limit: user.APILimit{Rate: 4}},
					"b": {Limit: user.APILimit{Rate: 2}},
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

				assert.Equal(t, user.AccessSpec{
					URL: "/user", Methods: []string{"GET"},
				}, s.Gw.getPolicy("per-path2").AccessRights["a"].AllowedURLs[0])

				assert.Equal(t, want, sess.AccessRights)
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
			name:     "Merge allowed fields for the same GraphQL API",
			policies: []string{"allowed-types1", "allowed-types2"},
			sessMatch: func(t *testing.T, s *user.SessionState) {
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
	ts := StartTest(nil)
	defer ts.Close()

	bmid, tests := ts.TestPrepareApplyPolicies()

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

	bmid, tests := ts.TestPrepareApplyPolicies()

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
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.policiesMu.RLock()
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

	ts.Gw.policiesByID = map[string]user.Policy{
		"policy1": policy1,
		"policy2": policy2,
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

<<<<<<< HEAD
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
=======
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
		Gw:                   g.Gw,
		Secret:               "test-secret",
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
		globalConf.UseDBAppConfigs = false // Disable dashboard integration for simpler test
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
		globalConf.UseDBAppConfigs = false // Disable dashboard integration for simpler test
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
		Gw:                   g.Gw,
		Secret:               "test-secret",
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
		globalConf.UseDBAppConfigs = false // Disable dashboard integration for simpler test
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
		Gw:                   g.Gw,
		Secret:               "test-secret",
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
				ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
				ts.Close()
				return ts
			},
			expectedError: "connection refused",
			description:   "Dashboard is completely down",
		},
		{
			name: "Network Timeout",
			serverFunc: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					// Simulate timeout by not responding at all
					// This ensures a predictable timeout error
					select {
					case <-time.After(5 * time.Second):
						// This will never be reached due to client timeout
					case <-w.(http.CloseNotifier).CloseNotify():
						// Client disconnected due to timeout
						return
					}
				}))
			},
			expectedError: "",
			description:   "Request times out before response",
		},
		{
			name: "Connection Dropped Mid-Response",
			serverFunc: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
			if tc.name == "Network Timeout" && err != nil {
				// Timeout errors can vary based on where the timeout occurs
				// Could be "context deadline exceeded", "unexpected end of JSON input", or "Client.Timeout"
				assert.True(t,
					strings.Contains(err.Error(), "context deadline exceeded") ||
						strings.Contains(err.Error(), "unexpected end of JSON input") ||
						strings.Contains(err.Error(), "Client.Timeout") ||
						strings.Contains(err.Error(), "timeout"),
					fmt.Sprintf("Expected timeout-related error, got: %v", err))
			} else if tc.expectedError != "" && err != nil {
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
		Gw:                   g.Gw,
		Secret:               "test-secret",
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
				Gw:                   g.Gw,
				Secret:               "test-secret",
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
>>>>>>> 48e93c638... [TT-15190] feat: Gateway Resilience Enhancement - Intelligent Auto-Recovery for Nonce Desynchronization (#7267)
}
