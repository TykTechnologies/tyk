package oauth2common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRenderJWTBearerScope pins the jwt-bearer scope rendering rule, one case
// per row of the design's scenario table: each scope that does not already
// contain "/" is prefixed with "audience/"; a scope containing "/" passes
// verbatim; nothing is ever invented.
func TestRenderJWTBearerScope(t *testing.T) {
	tests := []struct {
		name     string
		audience string
		scopes   []string
		want     string
	}{
		{
			name:     "audience + unqualified scopes are prefixed and space-joined in order",
			audience: "api://orders",
			scopes:   []string{"Orders.Read", "Orders.Write"},
			want:     "api://orders/Orders.Read api://orders/Orders.Write",
		},
		{
			name:     "explicit .default is prefixed like any scope",
			audience: "api://orders",
			scopes:   []string{".default"},
			want:     "api://orders/.default",
		},
		{
			name:     "audience with no scopes renders no scope at all",
			audience: "api://orders",
			scopes:   nil,
			want:     "",
		},
		{
			name:     "scopes with no audience pass verbatim, unprefixed",
			audience: "",
			scopes:   []string{"read", "write"},
			want:     "read write",
		},
		{
			name:     "already-qualified scope passes verbatim even with an audience set",
			audience: "api://orders",
			scopes:   []string{"api://billing/Refunds.Approve"},
			want:     "api://billing/Refunds.Approve",
		},
		{
			name:     "mixed qualified and unqualified list renders per entry",
			audience: "api://orders",
			scopes:   []string{"Orders.Read", "https://graph.microsoft.com/.default"},
			want:     "api://orders/Orders.Read https://graph.microsoft.com/.default",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, RenderJWTBearerScope(tt.audience, tt.scopes))
		})
	}
}
