package oas

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckRemoteMCPToolCatalogue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		primitives  []TykMCPServerPrimitive
		upstream    []string
		wantErr     string
		wantMissing []string
	}{
		{
			name:       "rename onto an untouched upstream tool",
			primitives: []TykMCPServerPrimitive{toolOverride("remove_repo", "delete_repo")},
			upstream:   []string{"remove_repo", "delete_repo", "create_issue"},
			wantErr:    `"delete_repo" would be exposed by two tools`,
		},
		{
			name: "swap and freed-name reuse",
			primitives: []TykMCPServerPrimitive{
				toolOverride("remove_repo", "delete_repo"),
				toolOverride("update_repo", "remove_repo"),
			},
			upstream: []string{"remove_repo", "update_repo", "create_issue"},
		},
		{
			name: "two-way swap of upstream tools",
			primitives: []TykMCPServerPrimitive{
				toolOverride("delete_repo", "remove_repo"),
				toolOverride("remove_repo", "delete_repo"),
			},
			upstream: []string{"delete_repo", "remove_repo"},
		},
		{
			name:        "missing source is reported but not an error",
			primitives:  []TykMCPServerPrimitive{toolOverride("archived_tool", "create_issue")},
			upstream:    []string{"create_issue"},
			wantMissing: []string{"archived_tool"},
		},
		{
			name:       "annotation-only override",
			primitives: []TykMCPServerPrimitive{{Source: TykMCPServerSource{ToolName: "delete_repo"}, Annotations: &DerivedToolAnnotations{DestructiveHint: boolRef(true)}}},
			upstream:   []string{"delete_repo", "create_issue"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			missing, err := CheckRemoteMCPToolCatalogue(&TykMCPServer{Primitives: tc.primitives}, tc.upstream)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantMissing, missing)
		})
	}
}
