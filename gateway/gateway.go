package gateway

import (
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/user"
)

// Gateway implements the Repository interface.
var _ model.Gateway = new(Gateway)

// PolicyIDs returns a list of IDs for each policy loaded in the gateway.
func (gw *Gateway) PolicyIDs() []string {
	return gw.policies.PolicyIDs()
}

// PolicyByID will return a Policy matching the passed Policy ID.
func (gw *Gateway) PolicyByID(id string) (user.Policy, bool) {
	return gw.policies.PolicyByID(id)
}

// PolicyCount will return the number of policies loaded in the gateway.
func (gw *Gateway) PolicyCount() int {
	return gw.policies.PolicyCount()
}

// SetPoliciesByID will update the internal policiesByID map with new policies.
// The key used will be the policy ID.
func (gw *Gateway) SetPoliciesByID(pols ...user.Policy) {
	gw.policies.Load(pols...)
}
