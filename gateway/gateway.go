package gateway

import (
	"github.com/TykTechnologies/tyk/user"
)

// SetPoliciesByID will update the internal policiesByID map with new policies.
// The key used will be the policy ID.
func (gw *Gateway) SetPoliciesByID(pols ...user.Policy) {
	gw.policies.Add(pols...)
}
