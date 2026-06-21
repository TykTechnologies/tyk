package user

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Verifies: STK-REQ-073, SYS-REQ-161, SW-REQ-148
// STK-REQ-073:STK-REQ-073-AC-01:acceptance
// SW-REQ-148:nominal:nominal
// SW-REQ-148:boundary:nominal
// SW-REQ-148:boundary:boundary
// SW-REQ-148:determinism:nominal
// SYS-REQ-161:determinism:nominal
func TestUserSessionLifetimeAndEndpointMapHelpers(t *testing.T) {
	t.Run("lifetime helpers", func(t *testing.T) {
		now := time.Now().Unix()

		tests := []struct {
			name    string
			session SessionState
			call    func(SessionState) int64
			want    int64
			delta   float64
		}{
			{
				name:    "global lifetime overrides local values",
				session: SessionState{SessionLifetime: 10, Expires: now + 100},
				call: func(s SessionState) int64 {
					return s.Lifetime(true, 20, true, 30)
				},
				want: 30,
			},
			{
				name:    "legacy session lifetime wins before fallback",
				session: SessionState{SessionLifetime: 40, Expires: now + 100},
				call: func(s SessionState) int64 {
					return s.Lifetime(false, 20, false, 0)
				},
				want: 40,
			},
			{
				name:    "fallback lifetime used without session lifetime",
				session: SessionState{},
				call: func(s SessionState) int64 {
					return s.Lifetime(false, 20, false, 0)
				},
				want: 20,
			},
			{
				name:    "respected future expiration extends shorter lifetime",
				session: SessionState{Expires: now + 100},
				call: func(s SessionState) int64 {
					return s.Lifetime(true, 20, false, 0)
				},
				want:  100,
				delta: 10,
			},
			{
				name:    "post expiry delete future returns ttl",
				session: SessionState{PostExpiryAction: PostExpiryActionDelete, Expires: now + 100},
				call: func(s SessionState) int64 {
					return s.Lifetime(true, 20, false, 0)
				},
				want:  100,
				delta: 10,
			},
			{
				name:    "post expiry retain indefinitely",
				session: SessionState{PostExpiryAction: PostExpiryActionRetain, PostExpiryGracePeriod: -1, Expires: now + 100},
				call: func(s SessionState) int64 {
					return s.Lifetime(false, 0, false, 0)
				},
				want: -1,
			},
			{
				name:    "post expiry retain with elapsed grace expires",
				session: SessionState{PostExpiryAction: PostExpiryActionRetain, PostExpiryGracePeriod: 10, Expires: now - 50},
				call: func(s SessionState) int64 {
					return s.Lifetime(false, 0, false, 0)
				},
				want: 1,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := tt.call(tt.session)
				if tt.delta > 0 {
					assert.InDelta(t, tt.want, got, tt.delta)
					return
				}
				assert.Equal(t, tt.want, got)
			})
		}

		defaultSession := SessionState{}
		deleteSession := SessionState{PostExpiryAction: PostExpiryActionDelete}
		retainSession := SessionState{PostExpiryAction: PostExpiryActionRetain}
		retainWithGraceSession := SessionState{PostExpiryAction: PostExpiryActionRetain, PostExpiryGracePeriod: 1}

		assert.False(t, defaultSession.hasNewExpiryBehaviour())
		assert.True(t, deleteSession.hasNewExpiryBehaviour())
		assert.False(t, retainSession.hasNewExpiryBehaviour())
		assert.True(t, retainWithGraceSession.hasNewExpiryBehaviour())
		assert.Equal(t, int64(0), calculateLifetime(true, 0, 30))
	})

	t.Run("endpoint map helpers", func(t *testing.T) {
		endpoints := Endpoints{
			{
				Path: "/users",
				Methods: EndpointMethods{
					{Name: "GET", Limit: RateLimit{Rate: 10, Per: 60}},
					{Name: "POST", Limit: RateLimit{Rate: 5, Per: 60}},
				},
			},
			{
				Path: "/users",
				Methods: EndpointMethods{
					{Name: "GET", Limit: RateLimit{Rate: 20, Per: 60}},
				},
			},
		}

		assert.Nil(t, Endpoints{}.Map())
		assert.Equal(t, EndpointsMap{
			"GET:/users":  {Rate: 20, Per: 60},
			"POST:/users": {Rate: 5, Per: 60},
		}, endpoints.Map())

		assert.Nil(t, EndpointsMap{}.Endpoints())
		assert.Equal(t, Endpoints{
			{
				Path: "/posts",
				Methods: EndpointMethods{
					{Name: "GET", Limit: RateLimit{Rate: 30, Per: 60}},
					{Name: "PUT", Limit: RateLimit{Rate: 15, Per: 60}},
				},
			},
			{
				Path: "/users",
				Methods: EndpointMethods{
					{Name: "POST", Limit: RateLimit{Rate: 5, Per: 60}},
				},
			},
		}, EndpointsMap{
			"POST:/users":       {Rate: 5, Per: 60},
			"PUT:/posts":        {Rate: 15, Per: 60},
			"GET:/posts":        {Rate: 30, Per: 60},
			"invalid":           {Rate: 1, Per: 1},
			"too:many:segments": {Rate: 2, Per: 2},
		}.Endpoints())
	})
}
