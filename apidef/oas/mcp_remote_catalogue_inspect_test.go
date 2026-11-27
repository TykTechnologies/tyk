package oas

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInspectRemoteMCPToolCatalogue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		primitives     []TykMCPServerPrimitive
		upstream       []string
		wantMissing    []string
		wantCollisions []RemoteMCPToolCollision
	}{
		{
			name:           "rename onto an untouched upstream tool is reported, not rejected",
			primitives:     []TykMCPServerPrimitive{toolOverride("remove_repo", "delete_repo")},
			upstream:       []string{"remove_repo", "delete_repo", "create_issue"},
			wantCollisions: []RemoteMCPToolCollision{{Name: "delete_repo", Source: "remove_repo"}},
		},
		{
			name: "every collision and missing source is reported",
			primitives: []TykMCPServerPrimitive{
				toolOverride("remove_repo", "delete_repo"),
				toolOverride("open_pr", "create_issue"),
				toolOverride("archived_tool", "old_tool"),
			},
			upstream:    []string{"remove_repo", "delete_repo", "open_pr", "create_issue"},
			wantMissing: []string{"archived_tool"},
			wantCollisions: []RemoteMCPToolCollision{
				{Name: "delete_repo", Source: "remove_repo"},
				{Name: "create_issue", Source: "open_pr"},
			},
		},
		{
			name: "swap and freed-name reuse do not collide",
			primitives: []TykMCPServerPrimitive{
				toolOverride("remove_repo", "delete_repo"),
				toolOverride("delete_repo", "remove_repo"),
			},
			upstream: []string{"remove_repo", "delete_repo"},
		},
		{
			name:        "an override whose source is missing cannot collide",
			primitives:  []TykMCPServerPrimitive{toolOverride("archived_tool", "create_issue")},
			upstream:    []string{"create_issue"},
			wantMissing: []string{"archived_tool"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			missing, collisions := InspectRemoteMCPToolCatalogue(&TykMCPServer{Primitives: tc.primitives}, tc.upstream)
			assert.Equal(t, tc.wantMissing, missing)
			assert.Equal(t, tc.wantCollisions, collisions)
		})
	}
	t.Run("nil extension", func(t *testing.T) {
		missing, collisions := InspectRemoteMCPToolCatalogue(nil, []string{"a"})
		assert.Nil(t, missing)
		assert.Nil(t, collisions)
	})
}
