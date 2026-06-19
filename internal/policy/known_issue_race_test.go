//go:build proof_race_reproducer
// +build proof_race_reproducer

package policy_test

import (
	"sync"
	"testing"

	"github.com/TykTechnologies/tyk/user"
)

// TestKnownIssue_SharedSessionConcurrentApplyRace is excluded from normal test
// runs because the expected proof signal is the Go race detector failing.
// Reproduces: KI-POLICY-SHARED-SESSION-RACE
// Verifies: SYS-REQ-068
func TestKnownIssue_SharedSessionConcurrentApplyRace(t *testing.T) {
	orgID := "org1"
	pol1 := user.Policy{
		ID:               "pol1",
		OrgID:            orgID,
		Rate:             100,
		Per:              60,
		QuotaMax:         5000,
		QuotaRenewalRate: 3600,
		AccessRights: map[string]user.AccessDefinition{
			"api1": {Versions: []string{"v1"}},
		},
	}
	pol2 := user.Policy{
		ID:               "pol2",
		OrgID:            orgID,
		Rate:             200,
		Per:              30,
		QuotaMax:         10000,
		QuotaRenewalRate: 7200,
		AccessRights: map[string]user.AccessDefinition{
			"api1": {Versions: []string{"v1"}},
		},
	}
	svc := newTestService(orgID, []user.Policy{pol1, pol2})
	session := &user.SessionState{MetaData: map[string]interface{}{}}
	session.SetPolicies("pol1", "pol2")

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = svc.Apply(session)
		}()
	}
	wg.Wait()
}

// TestKnownIssue_SharedSessionClearAndApplyRace is excluded from normal test
// runs because the expected proof signal is the Go race detector failing.
// Reproduces: KI-POLICY-SHARED-SESSION-RACE
// Verifies: SYS-REQ-068
func TestKnownIssue_SharedSessionClearAndApplyRace(t *testing.T) {
	orgID := "org1"
	pol := user.Policy{
		ID:               "pol1",
		OrgID:            orgID,
		Rate:             100,
		Per:              60,
		QuotaMax:         5000,
		QuotaRenewalRate: 3600,
		AccessRights: map[string]user.AccessDefinition{
			"api1": {Versions: []string{"v1"}},
		},
	}
	svc := newTestService(orgID, []user.Policy{pol})
	session := &user.SessionState{MetaData: map[string]interface{}{}}
	session.SetPolicies("pol1")

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = svc.Apply(session)
		}()
		go func() {
			defer wg.Done()
			_ = svc.ClearSession(session)
		}()
	}
	wg.Wait()
}
