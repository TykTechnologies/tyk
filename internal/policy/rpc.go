// SYS-REQ-008: RPC data loader mock for policy integration tests
package policy

import (
	"encoding/json"

	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/user"
)

// RPCDataLoaderMock is a policy-related test utility.
type RPCDataLoaderMock struct {
	ShouldConnect bool
	Policies      []user.Policy
	Apis          []model.MergedAPI
}

// Connect will return the connection status.
func (s *RPCDataLoaderMock) Connect() bool {
	return s.ShouldConnect
}

// GetApiDefinitions returns the internal Apis as a json string.
func (s *RPCDataLoaderMock) GetApiDefinitions(_ string, tags []string) string {
	if len(tags) > 1 {
		panic("not implemented")
	}

	apiList, err := json.Marshal(s.Apis)
	if err != nil { //mcdc:ignore json.Marshal cannot fail for []model.MergedAPI (no channels, funcs, or complex numbers)
		return ""
	}
	return string(apiList)
}

// GetPolicies returns the internal Policies as a json string.
func (s *RPCDataLoaderMock) GetPolicies(_ string) string {
	policyList, err := json.Marshal(s.Policies)
	if err != nil { //mcdc:ignore json.Marshal cannot fail for []user.Policy (no channels, funcs, or complex numbers)
		return ""
	}
	return string(policyList)
}
