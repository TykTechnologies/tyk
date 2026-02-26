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
