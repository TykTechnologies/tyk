package policy

import (
	"testing"

	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/user"
)

// Verifies: SYS-REQ-021 [boundary]
// MCDC SYS-REQ-021: apply_requested=T, result_returned=T => TRUE
func TestGreaterThanInt_BothPositive(t *testing.T) {
	// Covers: second == -1 evaluating to false (both args positive)
	if !greaterThanInt(10, 5) {
		t.Error("expected greaterThanInt(10, 5) = true")
	}
	if greaterThanInt(5, 10) {
		t.Error("expected greaterThanInt(5, 10) = false")
	}
}

// Verifies: SYS-REQ-021 [boundary]
// MCDC SYS-REQ-021: apply_requested=T, result_returned=T => TRUE
func TestGreaterThanInt64_BothPositive(t *testing.T) {
	// Covers: second == -1 evaluating to false (both args positive)
	if !greaterThanInt64(100, 50) {
		t.Error("expected greaterThanInt64(100, 50) = true")
	}
	if greaterThanInt64(50, 100) {
		t.Error("expected greaterThanInt64(50, 100) = false")
	}
}

// Verifies: SYS-REQ-021 [boundary]
// MCDC SYS-REQ-021: apply_requested=T, result_returned=T => TRUE
func TestGreaterThanInt_Sentinel(t *testing.T) {
	// first == -1 => always true
	if !greaterThanInt(-1, 5) {
		t.Error("expected greaterThanInt(-1, 5) = true")
	}
	// second == -1 => always false (when first != -1)
	if greaterThanInt(5, -1) {
		t.Error("expected greaterThanInt(5, -1) = false")
	}
}

// Verifies: SYS-REQ-008 [boundary]
// MCDC SYS-REQ-008: apply_requested=T, policy_found=F => TRUE
func TestPolicyByID_NonACLType(t *testing.T) {
	// Covers: store.go:57 ok=false branch (non-aclPolId type)
	store := NewStore(nil)
	_, found := store.PolicyByID(model.NewScopedCustomPolicyId("org", "nonexistent"))
	if found {
		t.Error("expected PolicyByID to return false for non-aclPolId type")
	}
}

// Verifies: SYS-REQ-048 [boundary]
// MCDC SYS-REQ-048: apply_requested=T, result_returned=T => TRUE
func TestApplyMCPPrimitiveLimits_DurationMerge(t *testing.T) {
	// Covers: apply.go:791 both branches of the compound condition
	svc := &Service{}
	// Duration = Per/Rate seconds.
	// "a": policy 10/10=1s < current 60/10=6s → policy wins (shorter)        → decision TRUE via left condition
	// "b": policy 60/10=6s, current Per=0 → curr.Duration()==0 → policy wins  → decision TRUE via right condition
	// "c": policy 60/10=6s >= current 10/10=1s, curr!=0 → current stays       → decision FALSE (both conditions false)
	policy := []user.MCPPrimitiveLimit{
		{Type: "tool", Name: "a", Limit: user.RateLimit{Rate: 10, Per: 10}},
		{Type: "tool", Name: "b", Limit: user.RateLimit{Rate: 10, Per: 60}},
		{Type: "tool", Name: "c", Limit: user.RateLimit{Rate: 10, Per: 60}},
	}
	current := []user.MCPPrimitiveLimit{
		{Type: "tool", Name: "a", Limit: user.RateLimit{Rate: 10, Per: 60}},
		{Type: "tool", Name: "b", Limit: user.RateLimit{Rate: 10, Per: 0}},
		{Type: "tool", Name: "c", Limit: user.RateLimit{Rate: 10, Per: 10}},
	}
	result := svc.ApplyMCPPrimitiveLimits(policy, current)
	for _, r := range result {
		if r.Name == "a" && r.Limit.Per != 10 {
			t.Errorf("expected Per=10 for tool 'a' (shorter duration wins), got %v", r.Limit.Per)
		}
		if r.Name == "b" && r.Limit.Per != 60 {
			t.Errorf("expected Per=60 for tool 'b' (replaces zero-duration), got %v", r.Limit.Per)
		}
		if r.Name == "c" && r.Limit.Per != 10 {
			t.Errorf("expected Per=10 for tool 'c' (current retained, policy duration longer), got %v", r.Limit.Per)
		}
	}
}
