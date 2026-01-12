package gateway

import (
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/user"
	"github.com/samber/lo"
)


// GetLoadedAPIIDs returns a list of all loaded API IDs with metadata.
// This is used for reporting loaded resources to MDCB.
func (gw *Gateway) GetLoadedAPIIDs() []model.LoadedAPIInfo {
	gw.apisMu.RLock()
	defer gw.apisMu.RUnlock()

	apis := make([]model.LoadedAPIInfo, 0, len(gw.apisByID))
	for apiID := range gw.apisByID {
		apis = append(apis, model.LoadedAPIInfo{
			APIID: apiID,
		})
	}
	return apis
}

// GetLoadedPolicyIDs returns a list of all loaded policy IDs with metadata.
// This is used for reporting loaded resources to MDCB.
func (gw *Gateway) GetLoadedPolicyIDs() []model.LoadedPolicyInfo {
	return lo.Map(gw.policies.AsSlice(), func(item user.Policy, _ int) model.LoadedPolicyInfo {
		return model.LoadedPolicyInfo{
			PolicyID: item.ID,
		}
	})
}

// SetPoliciesByID will update the internal policiesByID map with new policies.
// The key used will be the policy ID.
func (gw *Gateway) SetPoliciesByID(pols ...user.Policy) {
	gw.policies.Load(pols...)
}
