package user

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionState_AllowedIPs_Ignored(t *testing.T) {
	// This test proves that 'allowed_ips' is NOT supported on the key level (SessionState).
	// When a user tries to pass 'allowed_ips' via the Gateway API or Dashboard,
	// it is completely ignored during JSON unmarshaling because the field does not exist.
	
	jsonPayload := []byte(`{
		"allowance": 1000,
		"rate": 1000,
		"per": 60,
		"allowed_ips": ["192.168.1.1", "10.0.0.1"]
	}`)

	var session SessionState
	err := json.Unmarshal(jsonPayload, &session)
	require.NoError(t, err)

	// The standard fields are unmarshaled correctly
	assert.Equal(t, float64(1000), session.Allowance)
	assert.Equal(t, float64(1000), session.Rate)

	// But 'allowed_ips' is completely ignored. It is not in MetaData either,
	// because json.Unmarshal does not automatically put unknown fields into maps
	// unless explicitly handled by a custom UnmarshalJSON method.
	assert.Nil(t, session.MetaData)
	
	// Re-marshaling the session will NOT contain 'allowed_ips'
	marshaled, err := json.Marshal(session)
	require.NoError(t, err)
	assert.NotContains(t, string(marshaled), "allowed_ips")
}

func TestPolicy_AllowedIPs_Ignored(t *testing.T) {
	// This test proves that 'allowed_ips' is NOT supported on the policy level either.
	// If a user tries to pass 'allowed_ips' in a Policy definition, it is ignored.
	
	jsonPayload := []byte(`{
		"name": "My Policy",
		"rate": 1000,
		"per": 60,
		"allowed_ips": ["192.168.1.1", "10.0.0.1"]
	}`)

	var policy Policy
	err := json.Unmarshal(jsonPayload, &policy)
	require.NoError(t, err)

	assert.Equal(t, "My Policy", policy.Name)
	assert.Equal(t, float64(1000), policy.Rate)

	// 'allowed_ips' is ignored
	marshaled, err := json.Marshal(policy)
	require.NoError(t, err)
	assert.NotContains(t, string(marshaled), "allowed_ips")
}
