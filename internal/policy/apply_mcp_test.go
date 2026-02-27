package policy_test

import (
	"sort"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/policy"
	"github.com/TykTechnologies/tyk/user"
)

const testAPIID = "test-api"

// applyPolicies is a helper that applies a set of custom policies to a fresh session
// and returns the resulting AccessDefinition for testAPIID.
func applyPolicies(t *testing.T, policies []user.Policy) user.AccessDefinition {
	t.Helper()
	svc := policy.New(nil, nil, logrus.New())
	session := &user.SessionState{}
	session.SetCustomPolicies(policies)
	require.NoError(t, svc.Apply(session))
	return session.AccessRights[testAPIID]
}

// --- mergeACLRules via JSONRPCMethodsAccessRights ---

func TestApply_MergeACLRules_SinglePolicy(t *testing.T) {
	// A single policy's rules must be preserved in the session.
	pol := user.Policy{
		ID: "pol1",
		AccessRights: map[string]user.AccessDefinition{
			testAPIID: {
				APIID: testAPIID,
				JSONRPCMethodsAccessRights: user.AccessControlRules{
					Allowed: []string{"tools/call"},
					Blocked: []string{"admin/.*"},
				},
			},
		},
	}

	ad := applyPolicies(t, []user.Policy{pol})
	assert.Equal(t, []string{"tools/call"}, ad.JSONRPCMethodsAccessRights.Allowed)
	assert.Equal(t, []string{"admin/.*"}, ad.JSONRPCMethodsAccessRights.Blocked)
}

func TestApply_MergeACLRules_UnionAllowed(t *testing.T) {
	// Allowed lists from two policies are unioned.
	policies := []user.Policy{
		{ID: "pol1", AccessRights: map[string]user.AccessDefinition{
			testAPIID: {APIID: testAPIID, JSONRPCMethodsAccessRights: user.AccessControlRules{
				Allowed: []string{"tools/call", "ping"},
			}},
		}},
		{ID: "pol2", AccessRights: map[string]user.AccessDefinition{
			testAPIID: {APIID: testAPIID, JSONRPCMethodsAccessRights: user.AccessControlRules{
				Allowed: []string{"resources/read", "ping"},
			}},
		}},
	}

	ad := applyPolicies(t, policies)
	sort.Strings(ad.JSONRPCMethodsAccessRights.Allowed)
	assert.Equal(t, []string{"ping", "resources/read", "tools/call"}, ad.JSONRPCMethodsAccessRights.Allowed)
}

func TestApply_MergeACLRules_UnionBlocked(t *testing.T) {
	// Blocked lists from two policies are unioned.
	policies := []user.Policy{
		{ID: "pol1", AccessRights: map[string]user.AccessDefinition{
			testAPIID: {APIID: testAPIID, JSONRPCMethodsAccessRights: user.AccessControlRules{
				Blocked: []string{"admin/.*"},
			}},
		}},
		{ID: "pol2", AccessRights: map[string]user.AccessDefinition{
			testAPIID: {APIID: testAPIID, JSONRPCMethodsAccessRights: user.AccessControlRules{
				Blocked: []string{"debug"},
			}},
		}},
	}

	ad := applyPolicies(t, policies)
	sort.Strings(ad.JSONRPCMethodsAccessRights.Blocked)
	assert.Equal(t, []string{"admin/.*", "debug"}, ad.JSONRPCMethodsAccessRights.Blocked)
}

func TestApply_MergeACLRules_EmptyPolicyDoesNotClear(t *testing.T) {
	// A policy that has no rules configured must not clear rules set by another policy.
	policies := []user.Policy{
		{ID: "pol1", AccessRights: map[string]user.AccessDefinition{
			testAPIID: {APIID: testAPIID, JSONRPCMethodsAccessRights: user.AccessControlRules{
				Blocked: []string{"admin/.*"},
			}},
		}},
		{ID: "pol2", AccessRights: map[string]user.AccessDefinition{
			testAPIID: {APIID: testAPIID}, // no MCP rules
		}},
	}

	ad := applyPolicies(t, policies)
	assert.Equal(t, []string{"admin/.*"}, ad.JSONRPCMethodsAccessRights.Blocked)
}

// --- MCPAccessRights via Tools/Resources/Prompts ---

func TestApply_MergeMCPAccessRights_Tools(t *testing.T) {
	policies := []user.Policy{
		{ID: "pol1", AccessRights: map[string]user.AccessDefinition{
			testAPIID: {APIID: testAPIID, MCPAccessRights: user.MCPAccessRights{
				Tools: user.AccessControlRules{Allowed: []string{"weather", "search"}},
			}},
		}},
		{ID: "pol2", AccessRights: map[string]user.AccessDefinition{
			testAPIID: {APIID: testAPIID, MCPAccessRights: user.MCPAccessRights{
				Tools: user.AccessControlRules{Allowed: []string{"search", "translate"}},
			}},
		}},
	}

	ad := applyPolicies(t, policies)
	sort.Strings(ad.MCPAccessRights.Tools.Allowed)
	assert.Equal(t, []string{"search", "translate", "weather"}, ad.MCPAccessRights.Tools.Allowed)
}

func TestApply_MergeMCPAccessRights_ResourcesAndPrompts(t *testing.T) {
	policies := []user.Policy{
		{ID: "pol1", AccessRights: map[string]user.AccessDefinition{
			testAPIID: {APIID: testAPIID, MCPAccessRights: user.MCPAccessRights{
				Resources: user.AccessControlRules{Allowed: []string{"file://reports"}},
				Prompts:   user.AccessControlRules{Blocked: []string{"summarise"}},
			}},
		}},
	}

	ad := applyPolicies(t, policies)
	assert.Equal(t, []string{"file://reports"}, ad.MCPAccessRights.Resources.Allowed)
	assert.Equal(t, []string{"summarise"}, ad.MCPAccessRights.Prompts.Blocked)
}

// --- JSONRPCMethods rate limits ---

func TestApply_JSONRPCMethodLimits_SinglePolicy(t *testing.T) {
	pol := user.Policy{
		ID: "pol1", Rate: 100, Per: 60,
		AccessRights: map[string]user.AccessDefinition{
			testAPIID: {APIID: testAPIID, JSONRPCMethods: []user.JSONRPCMethodLimit{
				{Name: "tools/call", Limit: user.RateLimit{Rate: 10, Per: 60}},
			}},
		},
	}

	ad := applyPolicies(t, []user.Policy{pol})
	require.Len(t, ad.JSONRPCMethods, 1)
	assert.Equal(t, "tools/call", ad.JSONRPCMethods[0].Name)
	assert.Equal(t, float64(10), ad.JSONRPCMethods[0].Limit.Rate)
}

func TestApply_JSONRPCMethodLimits_HigherRateWins(t *testing.T) {
	// pol2 has a higher rate for the same method — it should win.
	policies := []user.Policy{
		{ID: "pol1", Rate: 100, Per: 60, AccessRights: map[string]user.AccessDefinition{
			testAPIID: {APIID: testAPIID, JSONRPCMethods: []user.JSONRPCMethodLimit{
				{Name: "tools/call", Limit: user.RateLimit{Rate: 10, Per: 60}},
			}},
		}},
		{ID: "pol2", Rate: 100, Per: 60, AccessRights: map[string]user.AccessDefinition{
			testAPIID: {APIID: testAPIID, JSONRPCMethods: []user.JSONRPCMethodLimit{
				{Name: "tools/call", Limit: user.RateLimit{Rate: 20, Per: 60}},
			}},
		}},
	}

	ad := applyPolicies(t, policies)
	require.Len(t, ad.JSONRPCMethods, 1)
	assert.Equal(t, float64(20), ad.JSONRPCMethods[0].Limit.Rate)
}

func TestApply_JSONRPCMethodLimits_NonOverlappingMerged(t *testing.T) {
	policies := []user.Policy{
		{ID: "pol1", Rate: 100, Per: 60, AccessRights: map[string]user.AccessDefinition{
			testAPIID: {APIID: testAPIID, JSONRPCMethods: []user.JSONRPCMethodLimit{
				{Name: "tools/call", Limit: user.RateLimit{Rate: 10, Per: 60}},
			}},
		}},
		{ID: "pol2", Rate: 100, Per: 60, AccessRights: map[string]user.AccessDefinition{
			testAPIID: {APIID: testAPIID, JSONRPCMethods: []user.JSONRPCMethodLimit{
				{Name: "resources/read", Limit: user.RateLimit{Rate: 5, Per: 60}},
			}},
		}},
	}

	ad := applyPolicies(t, policies)
	assert.Len(t, ad.JSONRPCMethods, 2)
}

// --- MCPPrimitives rate limits ---

func TestApply_MCPPrimitiveLimits_SinglePolicy(t *testing.T) {
	pol := user.Policy{
		ID: "pol1", Rate: 100, Per: 60,
		AccessRights: map[string]user.AccessDefinition{
			testAPIID: {APIID: testAPIID, MCPPrimitives: []user.MCPPrimitiveLimit{
				{Type: "tool", Name: "weather", Limit: user.RateLimit{Rate: 5, Per: 60}},
			}},
		},
	}

	ad := applyPolicies(t, []user.Policy{pol})
	require.Len(t, ad.MCPPrimitives, 1)
	assert.Equal(t, "weather", ad.MCPPrimitives[0].Name)
	assert.Equal(t, float64(5), ad.MCPPrimitives[0].Limit.Rate)
}

func TestApply_MCPPrimitiveLimits_HigherRateWins(t *testing.T) {
	policies := []user.Policy{
		{ID: "pol1", Rate: 100, Per: 60, AccessRights: map[string]user.AccessDefinition{
			testAPIID: {APIID: testAPIID, MCPPrimitives: []user.MCPPrimitiveLimit{
				{Type: "tool", Name: "weather", Limit: user.RateLimit{Rate: 5, Per: 60}},
			}},
		}},
		{ID: "pol2", Rate: 100, Per: 60, AccessRights: map[string]user.AccessDefinition{
			testAPIID: {APIID: testAPIID, MCPPrimitives: []user.MCPPrimitiveLimit{
				{Type: "tool", Name: "weather", Limit: user.RateLimit{Rate: 15, Per: 60}},
			}},
		}},
	}

	ad := applyPolicies(t, policies)
	require.Len(t, ad.MCPPrimitives, 1)
	assert.Equal(t, float64(15), ad.MCPPrimitives[0].Limit.Rate)
}

func TestApply_MCPPrimitiveLimits_SameNameDifferentTypeIsDistinct(t *testing.T) {
	// "weather" as a tool and "weather" as a resource are separate entries.
	pol := user.Policy{
		ID: "pol1", Rate: 100, Per: 60,
		AccessRights: map[string]user.AccessDefinition{
			testAPIID: {APIID: testAPIID, MCPPrimitives: []user.MCPPrimitiveLimit{
				{Type: "tool", Name: "weather", Limit: user.RateLimit{Rate: 10, Per: 60}},
				{Type: "resource", Name: "weather", Limit: user.RateLimit{Rate: 20, Per: 60}},
			}},
		},
	}

	ad := applyPolicies(t, []user.Policy{pol})
	assert.Len(t, ad.MCPPrimitives, 2)
}

// --- PerAPI path ---

const testAPIID2 = "test-api-2"

func applySession(t *testing.T, policies []user.Policy) *user.SessionState {
	t.Helper()
	svc := policy.New(nil, nil, logrus.New())
	session := &user.SessionState{}
	session.SetCustomPolicies(policies)
	require.NoError(t, svc.Apply(session))
	return session
}

func perAPIPolicy(id, apiID string, methods []user.JSONRPCMethodLimit, primitives []user.MCPPrimitiveLimit) user.Policy {
	return user.Policy{
		ID: id, Rate: 100, Per: 60,
		Partitions: user.PolicyPartitions{PerAPI: true},
		AccessRights: map[string]user.AccessDefinition{
			apiID: {
				APIID:          apiID,
				Limit:          user.APILimit{RateLimit: user.RateLimit{Rate: 100, Per: 60}},
				JSONRPCMethods: methods,
				MCPPrimitives:  primitives,
			},
		},
	}
}

func methodsByName(methods []user.JSONRPCMethodLimit) map[string]user.JSONRPCMethodLimit {
	m := make(map[string]user.JSONRPCMethodLimit, len(methods))
	for _, v := range methods {
		m[v.Name] = v
	}
	return m
}

func primitivesByKey(primitives []user.MCPPrimitiveLimit) map[string]user.MCPPrimitiveLimit {
	m := make(map[string]user.MCPPrimitiveLimit, len(primitives))
	for _, v := range primitives {
		m[v.Type+":"+v.Name] = v
	}
	return m
}

func TestApply_PerAPI_JSONRPCMethods_SinglePolicy(t *testing.T) {
	pol := perAPIPolicy("pol1", testAPIID, []user.JSONRPCMethodLimit{
		{Name: "tools/call", Limit: user.RateLimit{Rate: 10, Per: 60}},
		{Name: "resources/read", Limit: user.RateLimit{Rate: 5, Per: 60}},
	}, nil)

	ad := applyPolicies(t, []user.Policy{pol})
	require.Len(t, ad.JSONRPCMethods, 2)
	byName := methodsByName(ad.JSONRPCMethods)
	assert.Equal(t, float64(10), byName["tools/call"].Limit.Rate)
	assert.Equal(t, float64(5), byName["resources/read"].Limit.Rate)
}

func TestApply_PerAPI_JSONRPCMethods_NonOverlappingMerged(t *testing.T) {
	policies := []user.Policy{
		perAPIPolicy("pol1", testAPIID, []user.JSONRPCMethodLimit{
			{Name: "tools/call", Limit: user.RateLimit{Rate: 10, Per: 60}},
		}, nil),
		perAPIPolicy("pol2", testAPIID, []user.JSONRPCMethodLimit{
			{Name: "resources/read", Limit: user.RateLimit{Rate: 5, Per: 60}},
		}, nil),
	}

	ad := applyPolicies(t, policies)
	require.Len(t, ad.JSONRPCMethods, 2, "non-overlapping methods from both policies must survive")
	byName := methodsByName(ad.JSONRPCMethods)
	assert.Equal(t, float64(10), byName["tools/call"].Limit.Rate)
	assert.Equal(t, float64(5), byName["resources/read"].Limit.Rate)
}

func TestApply_PerAPI_JSONRPCMethods_HigherRateWins(t *testing.T) {
	// pol1: tools/call@20/60s (more permissive), pol2: tools/call@5/60s (more restrictive).
	policies := []user.Policy{
		perAPIPolicy("pol1", testAPIID, []user.JSONRPCMethodLimit{
			{Name: "tools/call", Limit: user.RateLimit{Rate: 20, Per: 60}},
		}, nil),
		perAPIPolicy("pol2", testAPIID, []user.JSONRPCMethodLimit{
			{Name: "tools/call", Limit: user.RateLimit{Rate: 5, Per: 60}},
		}, nil),
	}

	ad := applyPolicies(t, policies)
	require.Len(t, ad.JSONRPCMethods, 1)
	assert.Equal(t, float64(20), ad.JSONRPCMethods[0].Limit.Rate)
}

func TestApply_PerAPI_JSONRPCMethods_ThreePolicies_HighestRateWins(t *testing.T) {
	// pol1: 10, pol2: 30 (wins), pol3: 20.
	policies := []user.Policy{
		perAPIPolicy("pol1", testAPIID, []user.JSONRPCMethodLimit{
			{Name: "tools/call", Limit: user.RateLimit{Rate: 10, Per: 60}},
		}, nil),
		perAPIPolicy("pol2", testAPIID, []user.JSONRPCMethodLimit{
			{Name: "tools/call", Limit: user.RateLimit{Rate: 30, Per: 60}},
		}, nil),
		perAPIPolicy("pol3", testAPIID, []user.JSONRPCMethodLimit{
			{Name: "tools/call", Limit: user.RateLimit{Rate: 20, Per: 60}},
		}, nil),
	}

	ad := applyPolicies(t, policies)
	require.Len(t, ad.JSONRPCMethods, 1)
	assert.Equal(t, float64(30), ad.JSONRPCMethods[0].Limit.Rate)
}

func TestApply_PerAPI_JSONRPCMethods_ComplexOverlap(t *testing.T) {
	// pol1: tools/call@10, tools/list@5
	// pol2: tools/call@20 (wins), resources/read@15
	// expected: tools/call@20, tools/list@5, resources/read@15
	policies := []user.Policy{
		perAPIPolicy("pol1", testAPIID, []user.JSONRPCMethodLimit{
			{Name: "tools/call", Limit: user.RateLimit{Rate: 10, Per: 60}},
			{Name: "tools/list", Limit: user.RateLimit{Rate: 5, Per: 60}},
		}, nil),
		perAPIPolicy("pol2", testAPIID, []user.JSONRPCMethodLimit{
			{Name: "tools/call", Limit: user.RateLimit{Rate: 20, Per: 60}},
			{Name: "resources/read", Limit: user.RateLimit{Rate: 15, Per: 60}},
		}, nil),
	}

	ad := applyPolicies(t, policies)
	require.Len(t, ad.JSONRPCMethods, 3)
	byName := methodsByName(ad.JSONRPCMethods)
	assert.Equal(t, float64(20), byName["tools/call"].Limit.Rate)
	assert.Equal(t, float64(5), byName["tools/list"].Limit.Rate)
	assert.Equal(t, float64(15), byName["resources/read"].Limit.Rate)
}

func TestApply_PerAPI_MCPPrimitives_NonOverlappingMerged(t *testing.T) {
	policies := []user.Policy{
		perAPIPolicy("pol1", testAPIID, nil, []user.MCPPrimitiveLimit{
			{Type: "tool", Name: "weather", Limit: user.RateLimit{Rate: 10, Per: 60}},
		}),
		perAPIPolicy("pol2", testAPIID, nil, []user.MCPPrimitiveLimit{
			{Type: "resource", Name: "file", Limit: user.RateLimit{Rate: 5, Per: 60}},
		}),
	}

	ad := applyPolicies(t, policies)
	require.Len(t, ad.MCPPrimitives, 2, "both primitives must survive")
	byKey := primitivesByKey(ad.MCPPrimitives)
	assert.Equal(t, float64(10), byKey["tool:weather"].Limit.Rate)
	assert.Equal(t, float64(5), byKey["resource:file"].Limit.Rate)
}

func TestApply_PerAPI_MCPPrimitives_HigherRateWins(t *testing.T) {
	policies := []user.Policy{
		perAPIPolicy("pol1", testAPIID, nil, []user.MCPPrimitiveLimit{
			{Type: "tool", Name: "weather", Limit: user.RateLimit{Rate: 5, Per: 60}},
		}),
		perAPIPolicy("pol2", testAPIID, nil, []user.MCPPrimitiveLimit{
			{Type: "tool", Name: "weather", Limit: user.RateLimit{Rate: 15, Per: 60}},
		}),
	}

	ad := applyPolicies(t, policies)
	require.Len(t, ad.MCPPrimitives, 1)
	assert.Equal(t, float64(15), ad.MCPPrimitives[0].Limit.Rate)
}

func TestApply_PerAPI_MCPPrimitives_SameNameDifferentType_BothSurvive(t *testing.T) {
	// (tool, weather) and (resource, weather) are distinct composite keys.
	policies := []user.Policy{
		perAPIPolicy("pol1", testAPIID, nil, []user.MCPPrimitiveLimit{
			{Type: "tool", Name: "weather", Limit: user.RateLimit{Rate: 10, Per: 60}},
		}),
		perAPIPolicy("pol2", testAPIID, nil, []user.MCPPrimitiveLimit{
			{Type: "resource", Name: "weather", Limit: user.RateLimit{Rate: 20, Per: 60}},
		}),
	}

	ad := applyPolicies(t, policies)
	require.Len(t, ad.MCPPrimitives, 2)
	byKey := primitivesByKey(ad.MCPPrimitives)
	assert.Equal(t, float64(10), byKey["tool:weather"].Limit.Rate)
	assert.Equal(t, float64(20), byKey["resource:weather"].Limit.Rate)
}

func TestApply_PerAPI_BothFields_IndependentMerge(t *testing.T) {
	// pol1: tools/call@20, (tool,weather)@10
	// pol2: tools/call@5 (loses), resources/read@15, (tool,weather)@25 (wins)
	// expected: tools/call@20, resources/read@15, (tool,weather)@25
	policies := []user.Policy{
		perAPIPolicy("pol1", testAPIID,
			[]user.JSONRPCMethodLimit{
				{Name: "tools/call", Limit: user.RateLimit{Rate: 20, Per: 60}},
			},
			[]user.MCPPrimitiveLimit{
				{Type: "tool", Name: "weather", Limit: user.RateLimit{Rate: 10, Per: 60}},
			},
		),
		perAPIPolicy("pol2", testAPIID,
			[]user.JSONRPCMethodLimit{
				{Name: "tools/call", Limit: user.RateLimit{Rate: 5, Per: 60}},
				{Name: "resources/read", Limit: user.RateLimit{Rate: 15, Per: 60}},
			},
			[]user.MCPPrimitiveLimit{
				{Type: "tool", Name: "weather", Limit: user.RateLimit{Rate: 25, Per: 60}},
			},
		),
	}

	ad := applyPolicies(t, policies)

	require.Len(t, ad.JSONRPCMethods, 2)
	byName := methodsByName(ad.JSONRPCMethods)
	assert.Equal(t, float64(20), byName["tools/call"].Limit.Rate)
	assert.Equal(t, float64(15), byName["resources/read"].Limit.Rate)

	require.Len(t, ad.MCPPrimitives, 1)
	assert.Equal(t, float64(25), ad.MCPPrimitives[0].Limit.Rate)
}

func TestApply_PerAPI_OneFieldPerPolicy_BothSurvive(t *testing.T) {
	policies := []user.Policy{
		perAPIPolicy("pol1", testAPIID, []user.JSONRPCMethodLimit{
			{Name: "tools/call", Limit: user.RateLimit{Rate: 10, Per: 60}},
		}, nil),
		perAPIPolicy("pol2", testAPIID, nil, []user.MCPPrimitiveLimit{
			{Type: "tool", Name: "weather", Limit: user.RateLimit{Rate: 5, Per: 60}},
		}),
	}

	ad := applyPolicies(t, policies)
	require.Len(t, ad.JSONRPCMethods, 1, "method from pol1 must survive")
	require.Len(t, ad.MCPPrimitives, 1, "primitive from pol2 must survive")
}

func TestApply_PerAPI_MultipleAPIs_IndependentMerge(t *testing.T) {
	// Each policy covers two APIs; non-overlapping methods merge per API in isolation.
	pol1 := user.Policy{
		ID: "pol1", Rate: 100, Per: 60,
		Partitions: user.PolicyPartitions{PerAPI: true},
		AccessRights: map[string]user.AccessDefinition{
			testAPIID: {
				APIID: testAPIID,
				Limit: user.APILimit{RateLimit: user.RateLimit{Rate: 100, Per: 60}},
				JSONRPCMethods: []user.JSONRPCMethodLimit{
					{Name: "tools/call", Limit: user.RateLimit{Rate: 10, Per: 60}},
				},
			},
			testAPIID2: {
				APIID: testAPIID2,
				Limit: user.APILimit{RateLimit: user.RateLimit{Rate: 100, Per: 60}},
				JSONRPCMethods: []user.JSONRPCMethodLimit{
					{Name: "resources/read", Limit: user.RateLimit{Rate: 8, Per: 60}},
				},
			},
		},
	}
	pol2 := user.Policy{
		ID: "pol2", Rate: 100, Per: 60,
		Partitions: user.PolicyPartitions{PerAPI: true},
		AccessRights: map[string]user.AccessDefinition{
			testAPIID: {
				APIID: testAPIID,
				Limit: user.APILimit{RateLimit: user.RateLimit{Rate: 100, Per: 60}},
				JSONRPCMethods: []user.JSONRPCMethodLimit{
					{Name: "tools/list", Limit: user.RateLimit{Rate: 5, Per: 60}},
				},
			},
			testAPIID2: {
				APIID: testAPIID2,
				Limit: user.APILimit{RateLimit: user.RateLimit{Rate: 100, Per: 60}},
				JSONRPCMethods: []user.JSONRPCMethodLimit{
					{Name: "resources/write", Limit: user.RateLimit{Rate: 3, Per: 60}},
				},
			},
		},
	}

	sess := applySession(t, []user.Policy{pol1, pol2})

	api1 := sess.AccessRights[testAPIID]
	require.Len(t, api1.JSONRPCMethods, 2)
	api1Methods := methodsByName(api1.JSONRPCMethods)
	assert.Equal(t, float64(10), api1Methods["tools/call"].Limit.Rate)
	assert.Equal(t, float64(5), api1Methods["tools/list"].Limit.Rate)

	api2 := sess.AccessRights[testAPIID2]
	require.Len(t, api2.JSONRPCMethods, 2)
	api2Methods := methodsByName(api2.JSONRPCMethods)
	assert.Equal(t, float64(8), api2Methods["resources/read"].Limit.Rate)
	assert.Equal(t, float64(3), api2Methods["resources/write"].Limit.Rate)
}

func TestApply_PerAPI_MultipleAPIs_HigherRateWinsPerAPI(t *testing.T) {
	// api1: pol1 wins (20 > 5); api2: pol2 wins (30 > 10).
	pol1 := user.Policy{
		ID: "pol1", Rate: 100, Per: 60,
		Partitions: user.PolicyPartitions{PerAPI: true},
		AccessRights: map[string]user.AccessDefinition{
			testAPIID: {
				APIID: testAPIID,
				Limit: user.APILimit{RateLimit: user.RateLimit{Rate: 100, Per: 60}},
				JSONRPCMethods: []user.JSONRPCMethodLimit{
					{Name: "tools/call", Limit: user.RateLimit{Rate: 20, Per: 60}},
				},
			},
			testAPIID2: {
				APIID: testAPIID2,
				Limit: user.APILimit{RateLimit: user.RateLimit{Rate: 100, Per: 60}},
				JSONRPCMethods: []user.JSONRPCMethodLimit{
					{Name: "resources/read", Limit: user.RateLimit{Rate: 10, Per: 60}},
				},
			},
		},
	}
	pol2 := user.Policy{
		ID: "pol2", Rate: 100, Per: 60,
		Partitions: user.PolicyPartitions{PerAPI: true},
		AccessRights: map[string]user.AccessDefinition{
			testAPIID: {
				APIID: testAPIID,
				Limit: user.APILimit{RateLimit: user.RateLimit{Rate: 100, Per: 60}},
				JSONRPCMethods: []user.JSONRPCMethodLimit{
					{Name: "tools/call", Limit: user.RateLimit{Rate: 5, Per: 60}},
				},
			},
			testAPIID2: {
				APIID: testAPIID2,
				Limit: user.APILimit{RateLimit: user.RateLimit{Rate: 100, Per: 60}},
				JSONRPCMethods: []user.JSONRPCMethodLimit{
					{Name: "resources/read", Limit: user.RateLimit{Rate: 30, Per: 60}},
				},
			},
		},
	}

	sess := applySession(t, []user.Policy{pol1, pol2})

	api1 := sess.AccessRights[testAPIID]
	require.Len(t, api1.JSONRPCMethods, 1)
	assert.Equal(t, float64(20), api1.JSONRPCMethods[0].Limit.Rate)

	api2 := sess.AccessRights[testAPIID2]
	require.Len(t, api2.JSONRPCMethods, 1)
	assert.Equal(t, float64(30), api2.JSONRPCMethods[0].Limit.Rate)
}

func TestApply_PerAPI_MultipleAPIs_PartialCoverage(t *testing.T) {
	// pol1 covers testAPIID (methods) + testAPIID2 (primitives).
	// pol2 covers only testAPIID — testAPIID2 from pol1 must be preserved intact.
	pol1 := user.Policy{
		ID: "pol1", Rate: 100, Per: 60,
		Partitions: user.PolicyPartitions{PerAPI: true},
		AccessRights: map[string]user.AccessDefinition{
			testAPIID: {
				APIID: testAPIID,
				Limit: user.APILimit{RateLimit: user.RateLimit{Rate: 100, Per: 60}},
				JSONRPCMethods: []user.JSONRPCMethodLimit{
					{Name: "tools/call", Limit: user.RateLimit{Rate: 10, Per: 60}},
				},
			},
			testAPIID2: {
				APIID: testAPIID2,
				Limit: user.APILimit{RateLimit: user.RateLimit{Rate: 100, Per: 60}},
				MCPPrimitives: []user.MCPPrimitiveLimit{
					{Type: "tool", Name: "weather", Limit: user.RateLimit{Rate: 5, Per: 60}},
				},
			},
		},
	}
	pol2 := perAPIPolicy("pol2", testAPIID, []user.JSONRPCMethodLimit{
		{Name: "tools/list", Limit: user.RateLimit{Rate: 8, Per: 60}},
	}, nil)

	sess := applySession(t, []user.Policy{pol1, pol2})

	api1 := sess.AccessRights[testAPIID]
	require.Len(t, api1.JSONRPCMethods, 2)
	api1Methods := methodsByName(api1.JSONRPCMethods)
	assert.Equal(t, float64(10), api1Methods["tools/call"].Limit.Rate)
	assert.Equal(t, float64(8), api1Methods["tools/list"].Limit.Rate)

	api2 := sess.AccessRights[testAPIID2]
	require.Len(t, api2.MCPPrimitives, 1)
	assert.Equal(t, float64(5), api2.MCPPrimitives[0].Limit.Rate)
}
