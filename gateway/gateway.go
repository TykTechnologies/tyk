package gateway

import (
	"github.com/TykTechnologies/tyk/internal/policy"
	"github.com/TykTechnologies/tyk/user"
)

// Repository is a description of our Gateway API promises.
type Repository interface {
	policy.Repository
}

// Gateway implements the Repository interface.
var _ Repository = &Gateway{}

// PolicyIDs returns a list of IDs for each policy loaded in the gateway.
func (gw *Gateway) PolicyIDs() []string {
	gw.policiesMu.RLock()
	defer gw.policiesMu.RUnlock()

	result := make([]string, 0, len(gw.policiesByID))
	for id := range gw.policiesByID {
		result = append(result, id)
	}
	return result
}

// PolicyByID will return a Policy matching the passed Policy ID.
func (gw *Gateway) PolicyByID(id string) (user.Policy, bool) {
	gw.policiesMu.RLock()
	defer gw.policiesMu.RUnlock()

	pol, ok := gw.policiesByID[id]
	return pol, ok
}

// PolicyCount will return the number of policies loaded in the gateway.
func (gw *Gateway) PolicyCount() int {
	gw.policiesMu.RLock()
	defer gw.policiesMu.RUnlock()

	return len(gw.policiesByID)
}
