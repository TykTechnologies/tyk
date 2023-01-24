package oas

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestMiddleware(t *testing.T) {
	var emptyMiddleware Middleware

	var convertedAPI apidef.APIDefinition
	emptyMiddleware.ExtractTo(&convertedAPI)

	var resultMiddleware Middleware
	resultMiddleware.Fill(convertedAPI)

	assert.Equal(t, emptyMiddleware, resultMiddleware)
}

func TestGlobal(t *testing.T) {
	var emptyGlobal Global

	var convertedAPI apidef.APIDefinition
	emptyGlobal.ExtractTo(&convertedAPI)

	var resultGlobal Global
	resultGlobal.Fill(convertedAPI)

	assert.Equal(t, emptyGlobal, resultGlobal)
}

func TestPluginConfig(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var emptyPluginConfig PluginConfig

		var convertedAPI apidef.APIDefinition
		emptyPluginConfig.ExtractTo(&convertedAPI)

		var resultPluginConfig PluginConfig
		resultPluginConfig.Fill(convertedAPI)

		assert.Equal(t, emptyPluginConfig, resultPluginConfig)
	})

	t.Run("enum values", func(t *testing.T) {
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
			pluginConfig.ExtractTo(&api)
			assert.Equal(t, validDriver, api.CustomMiddleware.Driver)

			newPluginConfig := PluginConfig{}
			newPluginConfig.Fill(api)
			assert.Equal(t, pluginConfig, newPluginConfig)
		}
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
	t.Run("empty", func(t *testing.T) {
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
		authenticationPlugin := AuthenticationPlugin{
			Enabled: true,
			CustomPluginMiddleware: CustomPluginMiddleware{
				FunctionName: "authenticate",
				Path:         "/path/to/plugin",
				RawBodyOnly:  true,
			},
		}

		api := apidef.APIDefinition{}
		authenticationPlugin.ExtractTo(&api)
		assert.Equal(t, "authenticate", api.CustomMiddleware.AuthCheck.Name)
		assert.Equal(t, "/path/to/plugin", api.CustomMiddleware.AuthCheck.Path)
		assert.True(t, api.CustomMiddleware.AuthCheck.RawBodyOnly)
		assert.False(t, api.CustomMiddleware.AuthCheck.Disabled)

		newAuthenticationPlugin := AuthenticationPlugin{}
		newAuthenticationPlugin.Fill(api)
		assert.Equal(t, authenticationPlugin, newAuthenticationPlugin)
	})
}
