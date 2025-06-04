package policy

import (
	"github.com/TykTechnologies/tyk/user"
)

// Store is an in-memory policy storage object that implements the
// repository for policy access. We  do not implement concurrency
// protections here. Where order is important, use this.
type Store struct {
	policies []user.Policy
}

// NewStore returns a new policy.Store.
func NewStore(policies []user.Policy) *Store {
	return &Store{
		policies: policies,
	}
}

// PolicyIDs returns a list policy IDs in the store.
// It will return nil if no policies exist.
func (s *Store) PolicyIDs() []string {
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
func (s *Store) PolicyByID(id string) (user.Policy, bool) {
	for _, pol := range s.policies {
		if pol.ID == id {
			return pol, true
		}
	}
	return user.Policy{}, false
}

// PolicyCount returns the number of policies in the store.
func (s *Store) PolicyCount() int {
	return len(s.policies)
}
