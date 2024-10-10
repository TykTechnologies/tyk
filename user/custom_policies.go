package user

import (
	"encoding/json"
	"errors"
	"fmt"
)

// CustomPolicies returns a map of custom policies on the session.
// To preserve policy order, use GetCustomPolicies instead.
func (s *SessionState) CustomPolicies() (map[string]Policy, error) {
	customPolicies, err := s.GetCustomPolicies()
	if err != nil {
		return nil, err
	}

	result := make(map[string]Policy, len(customPolicies))
	for i := 0; i < len(customPolicies); i++ {
		result[customPolicies[i].ID] = customPolicies[i]
	}

	return result, nil
}

// GetCustomPolicies is like CustomPolicies but returns the list, preserving order.
func (s *SessionState) GetCustomPolicies() ([]Policy, error) {
	var (
		customPolicies []Policy
	)

	metadataPolicies, found := s.MetaData["policies"].([]interface{})
	if !found {
		return nil, errors.New("policies not found in metadata")
	}

	polJSON, err := json.Marshal(metadataPolicies)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata policies: %w", err)
	}

	if err := json.Unmarshal(polJSON, &customPolicies); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata policies: %w", err)
	}

	return customPolicies, err
}

// SetCustomPolicies sets custom policies into session metadata.
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
