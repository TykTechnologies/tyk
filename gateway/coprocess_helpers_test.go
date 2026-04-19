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

func TestProtoSessionState_Nil(t *testing.T) {
	assert.Nil(t, ProtoSessionState(nil))
}

func TestTykSessionState_Nil(t *testing.T) {
	assert.Nil(t, TykSessionState(nil))
}
