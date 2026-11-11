package tooloverride

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

func boolPtr(v bool) *bool { return &v }

func TestCompile(t *testing.T) {
	t.Parallel()

	t.Run("no primitives compiles to no view", func(t *testing.T) {
		view, err := Compile(nil)
		require.NoError(t, err)
		assert.Nil(t, view)

		view, err = Compile(&oas.TykMCPServer{})
		require.NoError(t, err)
		assert.Nil(t, view)
	})

	t.Run("invalid configuration is rejected", func(t *testing.T) {
		_, err := Compile(&oas.TykMCPServer{Primitives: []oas.TykMCPServerPrimitive{
			{Source: oas.TykMCPServerSource{ToolName: "a"}, Name: "same"},
			{Source: oas.TykMCPServerSource{ToolName: "b"}, Name: "same"},
		}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `"same" is a duplicate tool name`)
	})

	t.Run("view is detached from the configuration it was compiled from", func(t *testing.T) {
		ext := &oas.TykMCPServer{Primitives: []oas.TykMCPServerPrimitive{{
			Source:      oas.TykMCPServerSource{ToolName: "delete_repo"},
			Annotations: &oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)},
		}}}
		view, err := Compile(ext)
		require.NoError(t, err)

		*ext.Primitives[0].Annotations.DestructiveHint = false
		ext.Primitives[0].Source.ToolName = "other"

		override, ok := view.Override("delete_repo")
		require.True(t, ok)
		assert.Equal(t, []annotationField{{key: "destructiveHint", value: []byte("true")}}, override.annotations)
		_, ok = view.Override("other")
		assert.False(t, ok)
	})
}
