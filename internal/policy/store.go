package policy

import (
	"github.com/TykTechnologies/tyk/user"
)

// Store is an in-memory policy storage object that
// implements the repository for policy access. We
// do not implement concurrency protections here.
type Store struct {
	policies map[string]user.Policy
}

func NewStore(policies map[string]user.Policy) *Store {
	return &Store{
		policies: policies,
	}
}

func (s *Store) PolicyIDs() []string {
	policyIDs := make([]string, 0, len(s.policies))
	for _, val := range s.policies {
		policyIDs = append(policyIDs, val.ID)
	}
	return policyIDs
}

func (s *Store) PolicyByID(id string) (user.Policy, bool) {
	v, ok := s.policies[id]
	return v, ok
}

func (s *Store) PolicyCount() int {
	return len(s.policies)
}
