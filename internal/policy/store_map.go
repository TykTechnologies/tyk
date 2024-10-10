package policy

import (
	"github.com/TykTechnologies/tyk/user"
)

// StoreMap is same as Store, but doesn't preserve order.
type StoreMap struct {
	policies map[string]user.Policy
}

// NewStoreMap returns a new policy.StoreMap.
func NewStoreMap(policies map[string]user.Policy) *StoreMap {
	if len(policies) == 0 {
		policies = make(map[string]user.Policy)
	}

	return &StoreMap{
		policies: policies,
	}
}

// PolicyIDs returns a list policy IDs in the store.
// It will return nil if no policies exist.
func (s *StoreMap) PolicyIDs() []string {
	if len(s.policies) == 0 {
		return nil
	}

	policyIDs := make([]string, 0, len(s.policies))
	for _, val := range s.policies {
		policyIDs = append(policyIDs, val.ID)
	}
	return policyIDs
}

// PolicyByID returns a policy by ID.
func (s *StoreMap) PolicyByID(id string) (user.Policy, bool) {
	v, ok := s.policies[id]
	return v, ok
}

// PolicyCount returns the number of policies in the store.
func (s *StoreMap) PolicyCount() int {
	return len(s.policies)
}
