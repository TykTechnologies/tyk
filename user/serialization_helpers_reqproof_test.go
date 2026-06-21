package user

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Verifies: STK-REQ-072, SYS-REQ-160, SW-REQ-147
// STK-REQ-072:STK-REQ-072-AC-01:acceptance
// SW-REQ-147:nominal:nominal
// SW-REQ-147:boundary:nominal
// SW-REQ-147:boundary:boundary
// SW-REQ-147:determinism:nominal
// SYS-REQ-160:determinism:nominal
// MCDC SYS-REQ-160: user_serialization_helper_operation_terminal=T => TRUE
//
//mcdc:ignore SYS-REQ-160: user_serialization_helper_operation_terminal=F => FALSE -- the onboarded user serialization helper operations are synchronous local helpers that either classify empty values, report collection length, compare collection items for ordering, swap collection elements, or report method membership before returning; a non-terminal local result is not a reachable runtime state for these APIs [category: defensive] [reviewed: human:buger]
func TestUserSerializationAndEndpointCollectionHelpers(t *testing.T) {
	t.Run("IsZero helpers", func(t *testing.T) {
		tests := []struct {
			name string
			got  bool
			want bool
		}{
			{name: "empty field limits", got: FieldLimits{}.IsZero(), want: true},
			{name: "field max query depth", got: FieldLimits{MaxQueryDepth: 1}.IsZero()},
			{name: "empty basic auth", got: BasicAuthData{}.IsZero(), want: true},
			{name: "basic auth password", got: BasicAuthData{Password: "secret"}.IsZero()},
			{name: "basic auth hash", got: BasicAuthData{Hash: HashBCrypt}.IsZero()},
			{name: "empty jwt", got: JWTData{}.IsZero(), want: true},
			{name: "jwt secret", got: JWTData{Secret: "secret"}.IsZero()},
			{name: "empty monitor", got: Monitor{}.IsZero(), want: true},
			{name: "nil trigger limits", got: Monitor{TriggerLimits: nil}.IsZero(), want: true},
			{name: "non-empty trigger limits", got: Monitor{TriggerLimits: []float64{0.75}}.IsZero()},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.want, tt.got)
			})
		}
	})

	t.Run("Endpoints sort helpers", func(t *testing.T) {
		endpoints := Endpoints{
			{Path: "/z"},
			{Path: "/a"},
		}

		assert.Equal(t, 2, endpoints.Len())
		assert.False(t, endpoints.Less(0, 1))
		assert.True(t, endpoints.Less(1, 0))

		endpoints.Swap(0, 1)
		assert.Equal(t, "/a", endpoints[0].Path)
		assert.Equal(t, "/z", endpoints[1].Path)
	})

	t.Run("EndpointMethods sort and membership helpers", func(t *testing.T) {
		methods := EndpointMethods{
			{Name: "post"},
			{Name: "GET"},
		}

		assert.Equal(t, 2, methods.Len())
		assert.False(t, methods.Less(0, 1))
		assert.True(t, methods.Less(1, 0))
		assert.True(t, methods.Contains("POST"))
		assert.True(t, methods.Contains("get"))
		assert.False(t, methods.Contains("DELETE"))

		methods.Swap(0, 1)
		assert.Equal(t, "GET", methods[0].Name)
		assert.Equal(t, "post", methods[1].Name)
	})
}
