package gateway

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"

	"github.com/stretchr/testify/assert"
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
	gpm := GoPluginMiddleware{}
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
		apiSpec.VersionData.Versions = map[string]apidef.VersionInfo{"v1": {
			ExtendedPaths: apidef.ExtendedPathsSet{GoPlugin: make([]apidef.GoPluginMeta, 1)},
		}}

		assert.True(t, gpm.EnabledForSpec())
	})
}
