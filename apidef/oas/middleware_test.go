package oas

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestMiddleware(t *testing.T) {
	var emptyMiddleware Middleware

	var convertedAPI apidef.APIDefinition
	convertedAPI.SetDisabledFlags()
	emptyMiddleware.ExtractTo(&convertedAPI)

	var resultMiddleware Middleware
	resultMiddleware.Fill(convertedAPI)

	assert.Equal(t, emptyMiddleware, resultMiddleware)
}

func TestGlobal(t *testing.T) {
	var emptyGlobal Global

	var convertedAPI apidef.APIDefinition
	convertedAPI.SetDisabledFlags()
	emptyGlobal.ExtractTo(&convertedAPI)

	var resultGlobal Global
	resultGlobal.Fill(convertedAPI)

	assert.Equal(t, emptyGlobal, resultGlobal)
}

func TestPluginConfig(t *testing.T) {
	t.Parallel()
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		var emptyPluginConfig PluginConfig

		var convertedAPI apidef.APIDefinition
		convertedAPI.SetDisabledFlags()
		emptyPluginConfig.ExtractTo(&convertedAPI)

		var resultPluginConfig PluginConfig
		resultPluginConfig.Fill(convertedAPI)

		assert.Equal(t, emptyPluginConfig, resultPluginConfig)
	})

	t.Run("driver", func(t *testing.T) {
		t.Parallel()
		validDrivers := []apidef.MiddlewareDriver{
			apidef.OttoDriver,
			apidef.PythonDriver,
			apidef.LuaDriver,
			apidef.GrpcDriver,
			apidef.GoPluginDriver,
		}

		for _, validDriver := range validDrivers {
			pluginConfig := PluginConfig{
				Driver: validDriver,
			}

			api := apidef.APIDefinition{}
			api.SetDisabledFlags()
			pluginConfig.ExtractTo(&api)
			assert.Equal(t, validDriver, api.CustomMiddleware.Driver)

			newPluginConfig := PluginConfig{}
			newPluginConfig.Fill(api)
			assert.Equal(t, pluginConfig, newPluginConfig)
		}
	})

	t.Run("bundle", func(t *testing.T) {
		pluginPath := "/path/to/plugin"
		pluginConfig := PluginConfig{
			Driver: apidef.GoPluginDriver,
			Bundle: &PluginBundle{
				Enabled: true,
				Path:    pluginPath,
			},
		}

		api := apidef.APIDefinition{}
		pluginConfig.ExtractTo(&api)
		assert.Equal(t, apidef.GoPluginDriver, api.CustomMiddleware.Driver)
		assert.False(t, api.CustomMiddlewareBundleDisabled)
		assert.Equal(t, pluginPath, api.CustomMiddlewareBundle)

		newPluginConfig := PluginConfig{}
		newPluginConfig.Fill(api)
		assert.Equal(t, pluginConfig, newPluginConfig)
	})
}

func TestPluginBundle(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		var emptyPluginBundle PluginBundle

		var convertedAPI apidef.APIDefinition
		emptyPluginBundle.ExtractTo(&convertedAPI)

		var resultPluginBundle PluginBundle
		resultPluginBundle.Fill(convertedAPI)

		assert.Equal(t, emptyPluginBundle, resultPluginBundle)
	})

	t.Run("values", func(t *testing.T) {
		pluginPath := "/path/to/plugin"
		pluginBundle := PluginBundle{
			Enabled: true,
			Path:    pluginPath,
		}

		api := apidef.APIDefinition{}
		pluginBundle.ExtractTo(&api)
		assert.False(t, api.CustomMiddlewareBundleDisabled)
		assert.Equal(t, pluginPath, api.CustomMiddlewareBundle)

		newPluginBundle := PluginBundle{}
		newPluginBundle.Fill(api)
		assert.Equal(t, pluginBundle, newPluginBundle)
	})
}

func TestCORS(t *testing.T) {
	var emptyCORS CORS

	var convertedCORS apidef.CORSConfig
	emptyCORS.ExtractTo(&convertedCORS)

	var resultCORS CORS
	resultCORS.Fill(convertedCORS)

	assert.Equal(t, emptyCORS, resultCORS)
}

func TestCache(t *testing.T) {
	var emptyCache Cache

	var convertedCache apidef.CacheOptions
	emptyCache.ExtractTo(&convertedCache)

	var resultCache Cache
	resultCache.Fill(convertedCache)

	assert.Equal(t, emptyCache, resultCache)
}

func TestExtendedPaths(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		paths := make(Paths)

		var convertedEP apidef.ExtendedPathsSet
		paths.ExtractTo(&convertedEP)

		resultPaths := make(Paths)
		resultPaths.Fill(convertedEP)

		assert.Equal(t, paths, resultPaths)
	})

	t.Run("filled", func(t *testing.T) {
		paths := make(Paths)
		Fill(t, &paths, 0)

		var convertedEP apidef.ExtendedPathsSet
		paths.ExtractTo(&convertedEP)

		resultPaths := make(Paths)
		resultPaths.Fill(convertedEP)

		assert.Equal(t, paths, resultPaths)
	})
}

func TestTransformRequestBody(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var emptyTransformRequestBody TransformRequestBody

		var convertedTransformRequestBody apidef.TemplateMeta
		emptyTransformRequestBody.ExtractTo(&convertedTransformRequestBody)

		var resultTransformRequestBody TransformRequestBody
		resultTransformRequestBody.Fill(convertedTransformRequestBody)

		assert.Equal(t, emptyTransformRequestBody, resultTransformRequestBody)
	})
	t.Run("blob", func(t *testing.T) {
		transformReqBody := TransformRequestBody{
			Body:    "test body",
			Format:  apidef.RequestJSON,
			Enabled: true,
		}

		meta := apidef.TemplateMeta{}
		transformReqBody.ExtractTo(&meta)
		assert.Equal(t, apidef.TemplateMeta{
			Disabled: false,
			TemplateData: apidef.TemplateData{
				EnableSession:  true,
				Mode:           apidef.UseBlob,
				TemplateSource: "test body",
				Input:          apidef.RequestJSON,
			},
		}, meta)

		newTransformReqBody := TransformRequestBody{}
		newTransformReqBody.Fill(meta)
		assert.Equal(t, transformReqBody, newTransformReqBody)
	})

	t.Run("blob", func(t *testing.T) {
		transformReqBody := TransformRequestBody{
			Path:    "/opt/tyk-gateway/template.tmpl",
			Format:  apidef.RequestJSON,
			Enabled: false,
		}

		meta := apidef.TemplateMeta{}
		transformReqBody.ExtractTo(&meta)
		assert.Equal(t, apidef.TemplateMeta{
			Disabled: true,
			TemplateData: apidef.TemplateData{
				EnableSession:  true,
				Mode:           apidef.UseFile,
				TemplateSource: "/opt/tyk-gateway/template.tmpl",
				Input:          apidef.RequestJSON,
			},
		}, meta)

		newTransformReqBody := TransformRequestBody{}
		newTransformReqBody.Fill(meta)
		assert.Equal(t, transformReqBody, newTransformReqBody)
	})

	t.Run("blob should have precedence", func(t *testing.T) {
		transformReqBody := TransformRequestBody{
			Path:    "/opt/tyk-gateway/template.tmpl",
			Body:    "test body",
			Format:  apidef.RequestJSON,
			Enabled: true,
		}

		meta := apidef.TemplateMeta{}
		transformReqBody.ExtractTo(&meta)
		assert.Equal(t, apidef.TemplateMeta{
			Disabled: false,
			TemplateData: apidef.TemplateData{
				EnableSession:  true,
				Mode:           apidef.UseBlob,
				TemplateSource: "test body",
				Input:          apidef.RequestJSON,
			},
		}, meta)

		newTransformReqBody := TransformRequestBody{}
		newTransformReqBody.Fill(meta)
		expectedTransformReqBody := transformReqBody
		expectedTransformReqBody.Path = ""
		assert.Equal(t, expectedTransformReqBody, newTransformReqBody)
	})
}

func TestAuthenticationPlugin(t *testing.T) {
	t.Parallel()
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		var (
			emptyAuthenticationPlugin AuthenticationPlugin
			convertedAPI              apidef.APIDefinition
		)

		emptyAuthenticationPlugin.ExtractTo(&convertedAPI)

		var resultAuthenticationPlugin AuthenticationPlugin
		resultAuthenticationPlugin.Fill(convertedAPI)

		assert.Equal(t, emptyAuthenticationPlugin, resultAuthenticationPlugin)
	})

	t.Run("with values", func(t *testing.T) {
		t.Parallel()
		expectedAuthenticationPlugin := AuthenticationPlugin{
			Enabled:      true,
			FunctionName: "authenticate",
			Path:         "/path/to/plugin",
			RawBodyOnly:  true,
		}

		api := apidef.APIDefinition{}
		expectedAuthenticationPlugin.ExtractTo(&api)

		actualAuthenticationPlugin := AuthenticationPlugin{}
		actualAuthenticationPlugin.Fill(api)
		assert.Equal(t, expectedAuthenticationPlugin, actualAuthenticationPlugin)
	})
}

func TestPrePlugin(t *testing.T) {
	t.Parallel()
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		var (
			emptyPrePlugin PrePlugin
			convertedAPI   apidef.APIDefinition
		)

		convertedAPI.SetDisabledFlags()
		emptyPrePlugin.ExtractTo(&convertedAPI)

		var resultPrePlugin PrePlugin
		resultPrePlugin.Fill(convertedAPI)

		assert.Equal(t, emptyPrePlugin, resultPrePlugin)
	})

	t.Run("with values", func(t *testing.T) {
		t.Parallel()
		expectedPrePlugin := PrePlugin{
			Plugins: CustomPlugins{
				{
					Enabled:      true,
					FunctionName: "pre",
					Path:         "/path/to/plugin",
					RawBodyOnly:  true,
				},
			},
		}

		api := apidef.APIDefinition{}
		api.SetDisabledFlags()
		expectedPrePlugin.ExtractTo(&api)

		actualPrePlugin := PrePlugin{}
		actualPrePlugin.Fill(api)
		assert.Equal(t, expectedPrePlugin, actualPrePlugin)
	})
}

func TestCustomPlugins(t *testing.T) {
	t.Parallel()
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		var (
			emptyCustomPlugins CustomPlugins
			convertedMWDefs    []apidef.MiddlewareDefinition
		)

		emptyCustomPlugins.ExtractTo(convertedMWDefs)

		var resultCustomPlugins CustomPlugins
		resultCustomPlugins.Fill(convertedMWDefs)

		assert.Equal(t, emptyCustomPlugins, resultCustomPlugins)
	})

	t.Run("with values", func(t *testing.T) {
		t.Parallel()
		customPlugins := CustomPlugins{
			{
				Enabled:      true,
				FunctionName: "pre",
				Path:         "/path/to/plugin",
				RawBodyOnly:  true,
			},
		}

		mwDefs := make([]apidef.MiddlewareDefinition, 1)
		customPlugins.ExtractTo(mwDefs)
		assert.Equal(t, "pre", mwDefs[0].Name)
		assert.Equal(t, "/path/to/plugin", mwDefs[0].Path)
		assert.True(t, mwDefs[0].RawBodyOnly)
		assert.False(t, mwDefs[0].Disabled)

		newPrePlugin := make(CustomPlugins, 1)
		newPrePlugin.Fill(mwDefs)
		assert.Equal(t, customPlugins, newPrePlugin)
	})
}

func TestPostAuthenticationPlugin(t *testing.T) {
	t.Parallel()
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		var (
			emptyPostAuthPlugin PostAuthenticationPlugin
			convertedAPI        apidef.APIDefinition
		)

		convertedAPI.SetDisabledFlags()
		emptyPostAuthPlugin.ExtractTo(&convertedAPI)

		var resultPostAuthPlugin PostAuthenticationPlugin
		resultPostAuthPlugin.Fill(convertedAPI)

		assert.Equal(t, emptyPostAuthPlugin, resultPostAuthPlugin)
	})

	t.Run("with values", func(t *testing.T) {
		t.Parallel()
		expectedPostAuthPlugin := PostAuthenticationPlugin{
			Plugins: []CustomPlugin{
				{
					Enabled:      true,
					FunctionName: "postAuth",
					Path:         "/path/to/plugin",
					RawBodyOnly:  true,
				},
			},
		}

		api := apidef.APIDefinition{}
		api.SetDisabledFlags()
		expectedPostAuthPlugin.ExtractTo(&api)

		actualPostAuthPlugin := PostAuthenticationPlugin{}
		actualPostAuthPlugin.Fill(api)
		assert.Equal(t, expectedPostAuthPlugin, actualPostAuthPlugin)
	})
}
