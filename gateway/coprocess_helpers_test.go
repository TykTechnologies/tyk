package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/user"
)

func TestCoprocessSessionState_PostExpiry_RoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		action user.PostExpiryAction
		grace  int64
	}{
		{
			name:   "delete round-trip",
			action: user.PostExpiryActionDelete,
			grace:  0,
		},
		{
			name:   "retain grace=-1 round-trip",
			action: user.PostExpiryActionRetain,
			grace:  -1,
		},
		{
			name:   "retain grace=200 round-trip",
			action: user.PostExpiryActionRetain,
			grace:  200,
		},
		{
			name:   "zero values round-trip",
			action: "",
			grace:  0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			original := &user.SessionState{
				PostExpiryAction:      tc.action,
				PostExpiryGracePeriod: tc.grace,
			}

			// user → proto → user
			proto := ProtoSessionState(original)
			restored := TykSessionState(proto)

			assert.Equal(t, original.PostExpiryAction, restored.PostExpiryAction)
			assert.Equal(t, original.PostExpiryGracePeriod, restored.PostExpiryGracePeriod)
		})
	}
}

func BenchmarkProtoSessionState(b *testing.B) {
	session := &user.SessionState{
		Allowance:      100,
		Rate:           100,
		Per:            60,
		Expires:        100000,
		QuotaMax:       1000,
		QuotaRenews:    100000,
		QuotaRemaining: 500,
		OrgID:          "org-1",
		OauthClientID:  "client-1",
		OauthKeys: map[string]string{
			"key1": "val1",
			"key2": "val2",
		},
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIName: "API 1",
				APIID:   "api-1",
				Versions: []string{"Default"},
				AllowedURLs: []user.AccessSpec{
					{URL: "/path1", Methods: []string{"GET", "POST"}},
					{URL: "/path2", Methods: []string{"PUT", "DELETE"}},
				},
			},
			"api-2": {
				APIName: "API 2",
				APIID:   "api-2",
				Versions: []string{"v1", "v2"},
			},
		},
		MetaData: map[string]interface{}{
			"meta1": "value1",
			"meta2": 123,
			"meta3": true,
		},
		Tags: []string{"tag1", "tag2", "tag3"},
		Alias: "test-alias",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = ProtoSessionState(session)
	}
}
