package gateway

import (
	"github.com/TykTechnologies/tyk/internal/policy"
	"github.com/TykTechnologies/tyk/user"
)

type Repository interface {
	policy.Repository
}

var _ Repository = &Gateway{}

func (gw *Gateway) PolicyIDs() []string {
	gw.policiesMu.RLock()
	defer gw.policiesMu.RUnlock()

	result := make([]string, 0, len(gw.policiesByID))
	for id := range gw.policiesByID {
		result = append(result, id)
	}
	return result
}

func (gw *Gateway) PolicyByID(polID string) (user.Policy, bool) {
	gw.policiesMu.RLock()
	defer gw.policiesMu.RUnlock()

	pol, ok := gw.policiesByID[polID]
	return pol, ok
}

func (gw *Gateway) PolicyCount() int {
	gw.policiesMu.RLock()
	defer gw.policiesMu.RUnlock()

	return len(gw.policiesByID)
}
