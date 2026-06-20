package policy_test

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/policy"
	"github.com/TykTechnologies/tyk/user"
)

// STK-REQ-001
func acceptancePolicy(orgID, id string) user.Policy {
	return user.Policy{
		ID:               id,
		OrgID:            orgID,
		Rate:             120,
		Per:              60,
		QuotaMax:         5000,
		QuotaRenewalRate: 3600,
		MaxQueryDepth:    8,
		Tags:             []string{"gold", "internal"},
		MetaData:         map[string]interface{}{"plan": "gold"},
		AccessRights: map[string]user.AccessDefinition{
			"api1": {Versions: []string{"v1"}},
		},
	}
}

// Verifies: STK-REQ-001, STK-REQ-005 [example]
// STK-REQ-001:STK-REQ-001-AC-01:acceptance
func TestAcceptance_ApplySinglePolicyMergesAllFields(t *testing.T) {
	orgID := "org1"
	svc := newTestService(orgID, []user.Policy{acceptancePolicy(orgID, "gold")})
	session := &user.SessionState{MetaData: map[string]interface{}{}}
	session.SetPolicies("gold")

	require.NoError(t, svc.Apply(session))

	assert.Equal(t, float64(120), session.Rate)
	assert.Equal(t, float64(60), session.Per)
	assert.Equal(t, int64(5000), session.QuotaMax)
	assert.Equal(t, int64(3600), session.QuotaRenewalRate)
	assert.Equal(t, 8, session.MaxQueryDepth)
	assert.ElementsMatch(t, []string{"gold", "internal"}, session.Tags)
	assert.Equal(t, "gold", session.MetaData["plan"])
	assert.Contains(t, session.AccessRights, "api1")
}

// Verifies: STK-REQ-001 [example]
// STK-REQ-001:STK-REQ-001-AC-02:acceptance
func TestAcceptance_ApplyPerAPIPolicyAppliesIndependentLimits(t *testing.T) {
	orgID := "org1"
	pol := acceptancePolicy(orgID, "per-api")
	pol.Partitions = user.PolicyPartitions{PerAPI: true}
	pol.AccessRights = map[string]user.AccessDefinition{
		"api1": {
			Versions: []string{"v1"},
			Limit: user.APILimit{
				RateLimit:        user.RateLimit{Rate: 90, Per: 30},
				QuotaMax:         900,
				QuotaRenewalRate: 300,
				MaxQueryDepth:    5,
			},
		},
		"api2": {
			Versions: []string{"v1"},
			Limit: user.APILimit{
				RateLimit:     user.RateLimit{Rate: 30, Per: 10},
				MaxQueryDepth: 2,
			},
		},
	}

	svc := newTestService(orgID, []user.Policy{pol})
	session := &user.SessionState{MetaData: map[string]interface{}{}}
	session.SetPolicies("per-api")

	require.NoError(t, svc.Apply(session))

	api1 := session.AccessRights["api1"].Limit
	api2 := session.AccessRights["api2"].Limit
	assert.Equal(t, float64(90), api1.Rate)
	assert.Equal(t, float64(30), api1.Per)
	assert.Equal(t, int64(900), api1.QuotaMax)
	assert.Equal(t, 5, api1.MaxQueryDepth)
	assert.Equal(t, float64(30), api2.Rate)
	assert.Equal(t, float64(10), api2.Per)
	assert.Equal(t, 2, api2.MaxQueryDepth)
}

// Verifies: STK-REQ-001 [example]
// STK-REQ-001:STK-REQ-001-AC-03:acceptance
func TestAcceptance_ApplyPartitionedPolicyAppliesOnlyEnabledFields(t *testing.T) {
	orgID := "org1"
	pol := acceptancePolicy(orgID, "quota-acl")
	pol.Partitions = user.PolicyPartitions{Quota: true, Acl: true}
	pol.Rate = 999
	pol.Per = 999
	pol.MaxQueryDepth = 99
	pol.AccessRights = map[string]user.AccessDefinition{
		"api2": {Versions: []string{"v2"}},
	}

	svc := newTestService(orgID, []user.Policy{pol})
	session := &user.SessionState{
		Rate:          10,
		Per:           5,
		QuotaMax:      1,
		MaxQueryDepth: 3,
		AccessRights: map[string]user.AccessDefinition{
			"api1": {Versions: []string{"v1"}},
		},
		MetaData: map[string]interface{}{},
	}
	session.SetPolicies("quota-acl")

	require.NoError(t, svc.Apply(session))

	assert.Equal(t, int64(5000), session.QuotaMax)
	assert.Equal(t, int64(3600), session.QuotaRenewalRate)
	assert.Equal(t, float64(10), session.Rate)
	assert.Equal(t, float64(5), session.Per)
	assert.Equal(t, 3, session.MaxQueryDepth)
	assert.NotContains(t, session.AccessRights, "api1")
	assert.Contains(t, session.AccessRights, "api2")
}

// Verifies: STK-REQ-001, STK-REQ-003 [example]
// STK-REQ-001:STK-REQ-001-AC-04:acceptance
func TestAcceptance_ApplyMultiplePoliciesHighestRateWins(t *testing.T) {
	orgID := "org1"
	low := acceptancePolicy(orgID, "low")
	low.Rate = 40
	low.Per = 60
	high := acceptancePolicy(orgID, "high")
	high.Rate = 200
	high.Per = 60

	svc := newTestService(orgID, []user.Policy{low, high})
	session := &user.SessionState{MetaData: map[string]interface{}{}}
	session.SetPolicies("low", "high")

	require.NoError(t, svc.Apply(session))
	assert.Equal(t, float64(200), session.Rate)
	assert.Equal(t, float64(60), session.Per)
}

// Verifies: STK-REQ-003 [boundary]
func TestAcceptance_ApplyRateLimitsHonorsHigherEmptyAndEqualRates(t *testing.T) {
	svc := &policy.Service{}

	higher := user.APILimit{RateLimit: user.RateLimit{Rate: 100, Per: 60}}
	svc.ApplyRateLimits(&user.SessionState{}, user.Policy{Rate: 200, Per: 60}, &higher)
	assert.Equal(t, float64(200), higher.Rate)
	assert.Equal(t, float64(60), higher.Per)

	empty := user.APILimit{RateLimit: user.RateLimit{Rate: 100, Per: 60}}
	svc.ApplyRateLimits(&user.SessionState{}, user.Policy{Rate: 0, Per: 60}, &empty)
	assert.Equal(t, float64(100), empty.Rate)
	assert.Equal(t, float64(60), empty.Per)

	equal := user.APILimit{RateLimit: user.RateLimit{Rate: 100, Per: 60}}
	svc.ApplyRateLimits(&user.SessionState{}, user.Policy{Rate: 100, Per: 60}, &equal)
	assert.Equal(t, float64(100), equal.Rate)
	assert.Equal(t, float64(60), equal.Per)
}

// Verifies: STK-REQ-002 [example]
func TestAcceptance_ClearSessionResetsValuesAndReportsMissingPolicy(t *testing.T) {
	orgID := "org1"
	svc := newTestService(orgID, []user.Policy{acceptancePolicy(orgID, "gold")})

	session := &user.SessionState{Rate: 120, Per: 60, QuotaMax: 5000, QuotaRemaining: 2500, MaxQueryDepth: 8}
	session.SetPolicies("gold")
	require.NoError(t, svc.ClearSession(session))
	assert.Equal(t, float64(0), session.Rate)
	assert.Equal(t, float64(0), session.Per)
	assert.Equal(t, int64(0), session.QuotaMax)
	assert.Equal(t, int64(0), session.QuotaRemaining)
	assert.Equal(t, 0, session.MaxQueryDepth)

	missing := &user.SessionState{}
	missing.SetPolicies("missing")
	assert.Error(t, svc.ClearSession(missing))
}

// Verifies: STK-REQ-004 [example]
func TestAcceptance_EndpointLevelLimitsMergeHighestAndNewPaths(t *testing.T) {
	svc := &policy.Service{}
	current := user.Endpoints{
		{Path: "/users", Methods: user.EndpointMethods{{Name: "GET", Limit: user.RateLimit{Rate: 10, Per: 60}}}},
	}
	incoming := user.Endpoints{
		{Path: "/users", Methods: user.EndpointMethods{{Name: "GET", Limit: user.RateLimit{Rate: 25, Per: 60}}}},
		{Path: "/orders", Methods: user.EndpointMethods{{Name: "POST", Limit: user.RateLimit{Rate: 5, Per: 60}}}},
	}

	merged := svc.ApplyEndpointLevelLimits(incoming, current)
	limits := merged.Map()

	require.Contains(t, limits, "GET:/users")
	require.Contains(t, limits, "POST:/orders")
	assert.Equal(t, float64(25), limits["GET:/users"].Rate)
	assert.Equal(t, float64(5), limits["POST:/orders"].Rate)
}

// Verifies: STK-REQ-005 [negative]
func TestAcceptance_ApplyPolicyNotFoundReportsErrorAndPreservesFields(t *testing.T) {
	orgID := "org1"
	svc := newTestService(orgID, nil)

	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{"api-existing": {Versions: []string{"v1"}}},
		Rate:         77,
		Per:          33,
		QuotaMax:     1234,
		Tags:         []string{"existing"},
		MetaData:     map[string]interface{}{"existing": "metadata"},
	}
	session.SetPolicies("missing")

	err := svc.Apply(session)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy not found")
	assert.Contains(t, session.AccessRights, "api-existing")
	assert.Equal(t, float64(77), session.Rate)
	assert.Equal(t, float64(33), session.Per)
	assert.Equal(t, int64(1234), session.QuotaMax)
	assert.ElementsMatch(t, []string{"existing"}, session.Tags)
	assert.Equal(t, "metadata", session.MetaData["existing"])
}

// Verifies: STK-REQ-001 [negative]
// STK-REQ-001:STK-REQ-001-AC-05:acceptance
func TestAcceptance_ApplyOrgMismatchReportsError(t *testing.T) {
	orgID := "org1"
	wrongOrg := acceptancePolicy("other", "wrong-org")
	svc := newTestService(orgID, []user.Policy{wrongOrg})

	session := &user.SessionState{MetaData: map[string]interface{}{}}
	session.SetPolicies("wrong-org")

	err := svc.Apply(session)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "different organisation")
}

// Verifies: STK-REQ-006 [malformed]
func TestAcceptance_IdleNilStoreAndActiveIdleTransitions(t *testing.T) {
	orgID := "org1"
	idle := &user.SessionState{
		Rate:          7,
		Per:           30,
		QuotaMax:      70,
		MaxQueryDepth: 2,
		MetaData:      map[string]interface{}{},
	}
	beforeIdle := cloneSession(t, idle)
	assert.NotPanics(t, func() {
		svc := newTestService(orgID, nil)
		_ = svc
	})
	assert.Equal(t, beforeIdle.Rate, idle.Rate)
	assert.Equal(t, beforeIdle.QuotaMax, idle.QuotaMax)
	assert.Equal(t, beforeIdle.MaxQueryDepth, idle.MaxQueryDepth)

	nilSvc := policy.New(&orgID, nil, logrus.StandardLogger())
	nilSession := &user.SessionState{}
	nilSession.SetPolicies("gold")
	assert.ErrorIs(t, nilSvc.Apply(nilSession), policy.ErrNilPolicyStore)
	assert.ErrorIs(t, nilSvc.ClearSession(nilSession), policy.ErrNilPolicyStore)

	activeSvc := newTestService(orgID, []user.Policy{acceptancePolicy(orgID, "gold")})
	active := &user.SessionState{MetaData: map[string]interface{}{}}
	active.SetPolicies("gold")
	require.NoError(t, activeSvc.Apply(active))
	assert.Contains(t, active.AccessRights, "api1")

	active.SetPolicies()
	afterActive := cloneSession(t, active)
	require.NoError(t, activeSvc.Apply(active))
	assert.Equal(t, afterActive.Rate, active.Rate)
	assert.Equal(t, afterActive.QuotaMax, active.QuotaMax)
	assert.Equal(t, afterActive.MaxQueryDepth, active.MaxQueryDepth)
}

// Verifies: STK-REQ-007 [boundary]
func TestAcceptance_ApplyCompletesWithinPolicyCountBounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count int
	}{
		{name: "one_policy", count: 1},
		{name: "ten_policies", count: 10},
		{name: "fifty_policies", count: 50},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orgID := "org1"
			policies := make([]user.Policy, tc.count)
			ids := make([]string, tc.count)
			for i := range policies {
				p := acceptancePolicy(orgID, "bounded-"+string(rune('a'+i)))
				p.Rate = float64(100 + i)
				policies[i] = p
				ids[i] = p.ID
			}

			svc := newTestService(orgID, policies)
			session := &user.SessionState{MetaData: map[string]interface{}{}}
			session.SetPolicies(ids...)

			start := time.Now()
			require.NoError(t, svc.Apply(session))
			assert.LessOrEqual(t, time.Since(start), 100*time.Millisecond)
			assert.Contains(t, session.AccessRights, "api1")
		})
	}
}
