package user

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verifies: STK-REQ-071, SYS-REQ-159, SW-REQ-146
// STK-REQ-071:STK-REQ-071-AC-01:acceptance
// SW-REQ-146:nominal:nominal
// SW-REQ-146:boundary:nominal
// SW-REQ-146:boundary:boundary
// SW-REQ-146:error_handling:negative
// SW-REQ-146:error_handling:nominal
// SW-REQ-146:determinism:nominal
// SYS-REQ-159:error_handling:nominal
// SYS-REQ-159:error_handling:negative
// SYS-REQ-159:determinism:nominal
// STK-REQ-071:error_handling:negative
// MCDC SYS-REQ-159: user_session_state_operation_terminal=T => TRUE
//
//mcdc:ignore SYS-REQ-159: user_session_state_operation_terminal=F => FALSE -- the onboarded user session state operations are synchronous local helpers that either classify hash types, return empty session state, update or report modified flags, clone session collections, return MD5/key-hash values, panic for a missing key-hash cache, assign or compare policy IDs, return quota-limit tuples, report basic-auth state, or report active/quota predicate state before returning; a non-terminal local result is not a reachable runtime state for these APIs [category: defensive] [reviewed: human:buger]
func TestUserSessionStateHelpers(t *testing.T) {
	t.Run("hash types", func(t *testing.T) {
		tests := []struct {
			name string
			in   string
			want bool
		}{
			{name: "plain text empty is not a hash type"},
			{name: "unknown", in: "invalid"},
			{name: "sha256", in: "sha256", want: true},
			{name: "bcrypt", in: "bcrypt", want: true},
			{name: "murmur32", in: "murmur32", want: true},
			{name: "murmur64", in: "murmur64", want: true},
			{name: "murmur128", in: "murmur128", want: true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.want, IsHashType(tt.in))
			})
		}
	})

	t.Run("new session and modified flag", func(t *testing.T) {
		session := NewSessionState()
		require.NotNil(t, session)
		assert.False(t, session.IsModified())

		session.Touch()
		assert.True(t, session.IsModified())

		session.Reset()
		assert.False(t, session.IsModified())

		session.Touch()
		data, err := json.Marshal(session)
		require.NoError(t, err)

		var decoded SessionState
		require.NoError(t, json.Unmarshal(data, &decoded))
		assert.False(t, decoded.IsModified())
	})

	t.Run("clone copies collection headers", func(t *testing.T) {
		original := SessionState{
			AccessRights:  map[string]AccessDefinition{"api": {APIID: "api"}},
			OauthKeys:     map[string]string{"oauth": "key"},
			ApplyPolicies: []string{"policy-a"},
			MetaData:      map[string]interface{}{"owner": "team-a"},
			Tags:          []string{"tag-a"},
			OrgID:         "org-a",
		}

		clone := original.Clone()
		assert.Equal(t, original, clone)

		clone.AccessRights["api-b"] = AccessDefinition{APIID: "api-b"}
		clone.OauthKeys["oauth-b"] = "key-b"
		clone.ApplyPolicies[0] = "policy-b"
		clone.MetaData["owner"] = "team-b"
		clone.Tags[0] = "tag-b"

		assert.NotContains(t, original.AccessRights, "api-b")
		assert.NotContains(t, original.OauthKeys, "oauth-b")
		assert.Equal(t, []string{"policy-a"}, original.ApplyPolicies)
		assert.Equal(t, "team-a", original.MetaData["owner"])
		assert.Equal(t, []string{"tag-a"}, original.Tags)
	})

	t.Run("MD5 and key hash helpers", func(t *testing.T) {
		session := &SessionState{OrgID: "org-a"}
		assert.NotEmpty(t, session.MD5Hash())
		assert.Equal(t, session.MD5Hash(), session.MD5Hash())
		assert.True(t, session.KeyHashEmpty())
		require.Panics(t, func() { _ = session.KeyHash() })

		session.SetKeyHash("hash-a")
		assert.False(t, session.KeyHashEmpty())
		assert.Equal(t, "hash-a", session.KeyHash())
	})

	t.Run("policy ID helpers", func(t *testing.T) {
		tests := []struct {
			name string
			in   SessionState
			want []string
		}{
			{name: "none"},
			{name: "legacy fallback", in: SessionState{ApplyPolicyID: "legacy"}, want: []string{"legacy"}},
			{name: "multi policy wins", in: SessionState{ApplyPolicyID: "legacy", ApplyPolicies: []string{"a", "b"}}, want: []string{"a", "b"}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.want, tt.in.PolicyIDs())
			})
		}

		session := &SessionState{ApplyPolicyID: "legacy"}
		session.SetPolicies("b", "a")
		assert.Empty(t, session.ApplyPolicyID)
		assert.Equal(t, []string{"b", "a"}, session.ApplyPolicies)
		assert.True(t, session.PoliciesEqualTo([]string{"a", "b"}))
		assert.False(t, session.PoliciesEqualTo([]string{"a"}))
		assert.False(t, session.PoliciesEqualTo([]string{"a", "c"}))
	})

	t.Run("quota limit lookup", func(t *testing.T) {
		session := &SessionState{
			QuotaMax:         100,
			QuotaRemaining:   80,
			QuotaRenewalRate: 60,
			QuotaRenews:      10,
			AccessRights: map[string]AccessDefinition{
				"empty": {Limit: APILimit{}},
				"api": {
					Limit: APILimit{
						QuotaMax:         200,
						QuotaRemaining:   150,
						QuotaRenewalRate: 120,
						QuotaRenews:      20,
					},
				},
			},
		}

		assert.Equal(t, []int64{200, 150, 120, 20}, quotaTuple(session.GetQuotaLimitByAPIID("api")))
		assert.Equal(t, []int64{100, 80, 60, 10}, quotaTuple(session.GetQuotaLimitByAPIID("empty")))
		assert.Equal(t, []int64{100, 80, 60, 10}, quotaTuple(session.GetQuotaLimitByAPIID("missing")))
	})

	t.Run("basic auth and predicates", func(t *testing.T) {
		assert.False(t, (&SessionState{}).IsBasicAuth())
		assert.True(t, (&SessionState{BasicAuthData: BasicAuthData{Password: "secret"}}).IsBasicAuth())

		now := int64(100)
		tests := []struct {
			name          string
			session       SessionState
			active        bool
			consumedQuota bool
		}{
			{name: "active with consumed quota", session: SessionState{Expires: 101, QuotaMax: 10, QuotaRemaining: 9}, active: true, consumedQuota: true},
			{name: "inactive flag blocks active", session: SessionState{Expires: 101, IsInactive: true, QuotaMax: 10, QuotaRemaining: 9}, consumedQuota: true},
			{name: "expired blocks active", session: SessionState{Expires: 100, QuotaMax: 10, QuotaRemaining: 9}, consumedQuota: true},
			{name: "zero quota is not consumed", session: SessionState{Expires: 101}, active: true},
			{name: "remaining equal max is not consumed", session: SessionState{Expires: 101, QuotaMax: 10, QuotaRemaining: 10}, active: true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.active, tt.session.IsActiveAt(now))
				assert.Equal(t, tt.consumedQuota, tt.session.HasConsumedQuota())
			})
		}
	})
}

func quotaTuple(max, remaining, renewalRate, renews int64) []int64 {
	return []int64{max, remaining, renewalRate, renews}
}
