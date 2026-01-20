package policy

import (
	"maps"
	"slices"

	"github.com/samber/lo"

	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/user"
)

// StoreMap is same as Store, but doesn't preserve order.
type StoreMap struct {
	policies map[string]user.Policy
}

// NewStoreMap returns a new policy.StoreMap.
func NewStoreMap(policies map[string]user.Policy) *StoreMap {
	res := &StoreMap{
		policies: policies,
	}

	if res.policies == nil {
		res.policies = make(map[string]user.Policy)
	}

	return res
}

// PolicyIDs returns a list policy IDs in the store.
// It will return nil if no policies exist.
func (s *StoreMap) PolicyIDs() []model.PolicyID {
	if len(s.policies) == 0 {
		return nil
	}

	return lo.Map(slices.Collect(maps.Values(s.policies)), func(pol user.Policy, _ int) model.PolicyID {
		return model.NewScopedCustomPolicyId(pol.OrgID, pol.ID)
	})
}

// PolicyByID returns a policy by ID.
func (s *StoreMap) PolicyByID(id model.PolicyID) (pol user.Policy, ok bool) {
	pol, ok = s.policies[id.String()]
	return pol, ok
}

// PolicyCount returns the number of policies in the store.
func (s *StoreMap) PolicyCount() int {
	return len(s.policies)
}
