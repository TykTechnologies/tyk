package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

// TestLoadPlugin test the function to load a middleware goplugin
// ToDo: find out how to successfully load a plugin for testing
func TestLoadPlugin(t *testing.T) {
	plugin := GoPluginMiddleware{
		Path: "/any-fake-path",
	}

	pluginLoaded := plugin.loadPlugin()
	assert.Equal(t, false, pluginLoaded)
}

func TestGoPluginMiddleware_EnabledForSpec(t *testing.T) {
	gpm := GoPluginMiddleware{
		BaseMiddleware: &BaseMiddleware{},
	}
	apiSpec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	gpm.Spec = apiSpec

	assert.False(t, gpm.EnabledForSpec())

	t.Run("global go plugin", func(t *testing.T) {
		gpm.Path = "plugin.so"
		gpm.SymbolName = "name"

		assert.True(t, gpm.EnabledForSpec())

		gpm.Path = ""
		gpm.SymbolName = ""
	})

	t.Run("per path go plugin", func(t *testing.T) {
		ep := apidef.ExtendedPathsSet{GoPlugin: make([]apidef.GoPluginMeta, 1)}
		apiSpec.VersionData.Versions = map[string]apidef.VersionInfo{"v1": {
			ExtendedPaths: ep,
		}}

		assert.True(t, gpm.EnabledForSpec())

		t.Run("disabled", func(t *testing.T) {
			ep.GoPlugin[0].Disabled = true

			assert.False(t, gpm.EnabledForSpec())
		})
	})
}
