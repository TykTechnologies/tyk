package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
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

func TestCoprocessSessionState_AllowedURLs_RoundTrip(t *testing.T) {
	original := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				APIID:   "api-1",
				APIName: "API One",
				AllowedURLs: []user.AccessSpec{
					{URL: "/public$", Methods: []string{"GET"}},
					{
						URL:     "/connections$",
						Methods: []string{"GET"},
						Conditions: []user.AccessCondition{
							{
								On: apidef.All,
								Options: apidef.RoutingTriggerOptions{
									QueryValMatches: map[string]apidef.StringRegexMap{
										"persnbr": {Reverse: true},
										"account": {MatchPattern: "^[0-9]+$"},
									},
									HeaderMatches: map[string]apidef.StringRegexMap{
										"X-Role": {MatchPattern: "^admin$"},
									},
									PayloadMatches: apidef.StringRegexMap{MatchPattern: "ok"},
								},
							},
						},
					},
				},
			},
		},
	}

	restored := TykSessionState(ProtoSessionState(original))

	// The bridge used to allocate the slice by length and then append to it,
	// which padded every access definition with zero-valued specs. An empty
	// URL is an empty regex, so those padding entries matched every path and
	// handed a custom-auth session the whole API.
	assert.Len(t, restored.AccessRights["api-1"].AllowedURLs, 2)

	assert.Equal(t,
		original.AccessRights["api-1"].AllowedURLs,
		restored.AccessRights["api-1"].AllowedURLs,
		"conditions must survive the round trip: a spec that comes back without them grants more than it should")
}

func TestCoprocessSessionState_AllowedURLs_NoConditions(t *testing.T) {
	original := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {AllowedURLs: []user.AccessSpec{{URL: "/a$", Methods: []string{"GET"}}}},
		},
	}

	restored := TykSessionState(ProtoSessionState(original))

	assert.Nil(t, restored.AccessRights["api-1"].AllowedURLs[0].Conditions,
		"a spec without conditions must not gain an empty one")
}
