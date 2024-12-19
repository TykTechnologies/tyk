package gateway

import (
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/user"
)

// Gateway implements the Repository interface.
var _ model.Gateway = &Gateway{}

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

// SetPolicies updates the internal policy map with a new policy map.
func (gw *Gateway) SetPolicies(pols map[string]user.Policy) {
	gw.policiesMu.Lock()
	defer gw.policiesMu.Unlock()

	gw.policiesByID = pols
}

// SetPoliciesByID will update the internal policiesByID map with new policies.
// The key used will be the policy ID.
func (gw *Gateway) SetPoliciesByID(pols ...user.Policy) {
	gw.policiesMu.Lock()
	defer gw.policiesMu.Unlock()

	for _, pol := range pols {
		gw.policiesByID[pol.ID] = pol
	}
}
