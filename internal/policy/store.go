// SYS-REQ-008: in-memory policy storage for Apply and ClearSession operations
package policy

import (
	"github.com/samber/lo"

	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/user"
)

// Store is an in-memory policy storage object that implements the
// repository for policy access. We  do not implement concurrency
// protections here. Where order is important, use this.
type Store struct {
	policies []user.Policy
}

type aclPolId struct {
	model.BasePolicyId
	pol *user.Policy
}

func (a aclPolId) String() string {
	return a.pol.ID
}

func (a aclPolId) IsIdentifierOf(_ user.Policy) bool {
	return false
}

// SYS-REQ-008
// NewStore returns a new policy.Store.
func NewStore(policies []user.Policy) *Store {
	return &Store{
		policies: policies,
	}
}

// SYS-REQ-008
// PolicyIDs returns a list policy IDs in the store.
// It will return nil if no policies exist.
func (s *Store) PolicyIDs() []model.PolicyID {
	if s.policies == nil {
		return nil
	}

	return lo.Map(s.policies, func(pol user.Policy, _ int) model.PolicyID {
		return aclPolId{
			pol: &pol,
		}
	})
}

// SYS-REQ-008
// PolicyByID returns a policy by ID.
func (s *Store) PolicyByID(id model.PolicyID) (user.Policy, bool) {
	if cast, ok := id.(aclPolId); ok {
		return *cast.pol, true
	}
	return user.Policy{}, false
}

// SYS-REQ-008
// PolicyCount returns the number of policies in the store.
func (s *Store) PolicyCount() int {
	return len(s.policies)
}
