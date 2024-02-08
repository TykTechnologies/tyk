package user

import (
	"encoding/json"
	"errors"
	"fmt"
)

func (s *SessionState) CustomPolicies() (map[string]Policy, error) {
	var (
		customPolicies []Policy
		ret            map[string]Policy
	)

	metadataPolicies, found := s.MetaData["policies"].([]interface{})
	if !found {
		return nil, errors.New("policies not found in metadata")
	}

	polJSON, err := json.Marshal(metadataPolicies)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata policies: %w", err)
	}

	_ = json.Unmarshal(polJSON, &customPolicies)

	ret = make(map[string]Policy, len(customPolicies))
	for i := 0; i < len(customPolicies); i++ {
		ret[customPolicies[i].ID] = customPolicies[i]
	}

	return ret, nil
}

func (s *SessionState) SetCustomPolicies(list []Policy) {
	if s.MetaData == nil {
		s.MetaData = make(map[string]interface{})
	}

	policies := []interface{}{}
	for pol := range list {
		policies = append(policies, list[pol])
	}
	s.MetaData["policies"] = policies
}
