package oas

import (
	"encoding/json"
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

	t.Run("plugins", func(t *testing.T) {
		customPlugins := CustomPlugins{
			CustomPlugin{
				Enabled:      true,
				FunctionName: "func",
				Path:         "/path",
			},
		}

		var pluginMW = Middleware{
			Global: &Global{
				PrePlugin: &PrePlugin{
					Plugins: customPlugins,
				},
				PostAuthenticationPlugin: &PostAuthenticationPlugin{
					Plugins: customPlugins,
				},
				PostPlugin: &PostPlugin{
					Plugins: customPlugins,
				},
				ResponsePlugin: &ResponsePlugin{
					Plugins: customPlugins,
				},
			},
		}

		var convertedAPI apidef.APIDefinition
		convertedAPI.SetDisabledFlags()

		pluginMW.ExtractTo(&convertedAPI)

		var resultMiddleware = Middleware{
			Global: &Global{
				PrePlugin:                &PrePlugin{},
				PostAuthenticationPlugin: &PostAuthenticationPlugin{},
				PostPlugin:               &PostPlugin{},
				ResponsePlugin:           &ResponsePlugin{},
			},
		}
		resultMiddleware.Fill(convertedAPI)

		expectedMW := Middleware{
			Global: &Global{
				PrePlugins:                customPlugins,
				PostAuthenticationPlugins: customPlugins,
				PostPlugins:               customPlugins,
				ResponsePlugins:           customPlugins,
			},
		}
		assert.Equal(t, expectedMW, resultMiddleware)
	})

	t.Run("response plugins", func(t *testing.T) {
		customPlugins := CustomPlugins{
			CustomPlugin{
				Enabled:      true,
				FunctionName: "func1",
				Path:         "/path1",
			},
		}

		responsePlugins := CustomPlugins{
			CustomPlugin{
				Enabled:      true,
				FunctionName: "func2",
				Path:         "/path2",
			},
			CustomPlugin{
				Enabled:      true,
				FunctionName: "func3",
				Path:         "/path3",
			},
		}

		var pluginMW = Middleware{
			Global: &Global{
				ResponsePlugin: &ResponsePlugin{
					Plugins: customPlugins,
				},
				ResponsePlugins: responsePlugins,
			},
		}

		var convertedAPI apidef.APIDefinition
		convertedAPI.SetDisabledFlags()

		pluginMW.ExtractTo(&convertedAPI)

		// regression  https://tyktech.atlassian.net/browse/TT-12762
		assert.Equal(t, len(responsePlugins), len(convertedAPI.CustomMiddleware.Response))

		var resultMiddleware = Middleware{
			Global: &Global{
				ResponsePlugin: &ResponsePlugin{},
			},
		}
		resultMiddleware.Fill(convertedAPI)

		expectedMW := Middleware{
			Global: &Global{
				ResponsePlugins: responsePlugins,
			},
		}

		assert.Equal(t, expectedMW, resultMiddleware)
	})
}

func TestGlobal(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var emptyGlobal Global

		var convertedAPI apidef.APIDefinition
		convertedAPI.SetDisabledFlags()
		emptyGlobal.ExtractTo(&convertedAPI)

		var resultGlobal Global
		resultGlobal.Fill(convertedAPI)

		assert.Equal(t, emptyGlobal, resultGlobal)
	})

	t.Run("json", func(t *testing.T) {
		g := Global{
			PrePlugin: &PrePlugin{
				Plugins: make(CustomPlugins, 1),
			},
			PostAuthenticationPlugin: &PostAuthenticationPlugin{
				Plugins: make(CustomPlugins, 1),
			},
			PostPlugin: &PostPlugin{
				Plugins: make(CustomPlugins, 1),
			},
			ResponsePlugin: &ResponsePlugin{
				Plugins: make(CustomPlugins, 1),
			},
		}

		body, err := json.Marshal(&g)
		assert.NoError(t, err)

		var updatedGlobal Global
		assert.NoError(t, json.Unmarshal(body, &updatedGlobal))
		assert.Nil(t, updatedGlobal.PrePlugin)
		assert.NotNil(t, updatedGlobal.PrePlugins)
		assert.Nil(t, updatedGlobal.PostAuthenticationPlugin)
		assert.NotNil(t, updatedGlobal.PostAuthenticationPlugins)
		assert.Nil(t, updatedGlobal.PostPlugin)
		assert.NotNil(t, updatedGlobal.PostPlugins)
		assert.Nil(t, updatedGlobal.ResponsePlugin)
		assert.NotNil(t, updatedGlobal.ResponsePlugins)
	})
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
		api.SetDisabledFlags()
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

func TestTransformBody(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var emptyTransformBody TransformBody

		var convertedTransformBody apidef.TemplateMeta
		emptyTransformBody.ExtractTo(&convertedTransformBody)

		var resultTransformBody TransformBody
		resultTransformBody.Fill(convertedTransformBody)

		assert.Equal(t, emptyTransformBody, resultTransformBody)
	})
	t.Run("blob", func(t *testing.T) {
		transformReqBody := TransformBody{
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

		newTransformReqBody := TransformBody{}
		newTransformReqBody.Fill(meta)
		assert.Equal(t, transformReqBody, newTransformReqBody)
	})

	t.Run("path", func(t *testing.T) {
		transformReqBody := TransformBody{
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

		newTransformReqBody := TransformBody{}
		newTransformReqBody.Fill(meta)
		assert.Equal(t, transformReqBody, newTransformReqBody)
	})

	t.Run("blob should have precedence", func(t *testing.T) {
		transformReqBody := TransformBody{
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

		newTransformReqBody := TransformBody{}
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

		convertedAPI.SetDisabledFlags()
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
		api.SetDisabledFlags()
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
	t.Run("nil", func(t *testing.T) {
		var (
			nilCustomPlugins *CustomPlugins
			mwDefs           []apidef.MiddlewareDefinition
		)
		nilCustomPlugins.ExtractTo(mwDefs)
		assert.Nil(t, mwDefs)
	})

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

func TestPostPlugin(t *testing.T) {
	t.Parallel()
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		var (
			emptyPostPlugin PostPlugin
			convertedAPI    apidef.APIDefinition
		)

		convertedAPI.SetDisabledFlags()
		emptyPostPlugin.ExtractTo(&convertedAPI)

		var resultPostPlugin PostPlugin
		resultPostPlugin.Fill(convertedAPI)

		assert.Equal(t, emptyPostPlugin, resultPostPlugin)
	})

	t.Run("with values", func(t *testing.T) {
		t.Parallel()
		expectedPostPlugin := PostPlugin{
			Plugins: CustomPlugins{
				{
					Enabled:      true,
					FunctionName: "post",
					Path:         "/path/to/plugin",
					RawBodyOnly:  true,
				},
			},
		}

		api := apidef.APIDefinition{}
		api.SetDisabledFlags()
		expectedPostPlugin.ExtractTo(&api)

		actualPostPlugin := PostPlugin{}
		actualPostPlugin.Fill(api)
		assert.Equal(t, expectedPostPlugin, actualPostPlugin)
	})
}

func TestResponsePlugin(t *testing.T) {
	t.Parallel()
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		var (
			emptyResponsePlugin ResponsePlugin
			convertedAPI        apidef.APIDefinition
		)

		convertedAPI.SetDisabledFlags()
		emptyResponsePlugin.ExtractTo(&convertedAPI)

		var resultResponsePlugin ResponsePlugin
		resultResponsePlugin.Fill(convertedAPI)

		assert.Equal(t, emptyResponsePlugin, resultResponsePlugin)
	})

	t.Run("with values", func(t *testing.T) {
		t.Parallel()
		expectedResponsePlugin := ResponsePlugin{
			Plugins: CustomPlugins{
				{
					Enabled:      true,
					FunctionName: "response",
					Path:         "/path/to/plugin",
					RawBodyOnly:  true,
				},
			},
		}

		api := apidef.APIDefinition{}
		api.SetDisabledFlags()
		expectedResponsePlugin.ExtractTo(&api)

		actualResponsePlugin := ResponsePlugin{}
		actualResponsePlugin.Fill(api)
		assert.Equal(t, expectedResponsePlugin, actualResponsePlugin)
	})
}

func TestPluginConfigData(t *testing.T) {
	t.Parallel()
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		var (
			emptyPluginConfigData PluginConfigData
			convertedAPI          apidef.APIDefinition
		)

		convertedAPI.SetDisabledFlags()
		emptyPluginConfigData.ExtractTo(&convertedAPI)

		var resultPluginConfigData PluginConfigData
		resultPluginConfigData.Fill(convertedAPI)

		assert.Equal(t, emptyPluginConfigData, resultPluginConfigData)
	})

	t.Run("values", func(t *testing.T) {
		t.Parallel()
		expectedPluginConfigData := PluginConfigData{
			Enabled: true,
			Value: map[string]interface{}{
				"foo": "bar",
			},
		}

		api := apidef.APIDefinition{}
		api.SetDisabledFlags()
		expectedPluginConfigData.ExtractTo(&api)

		actualPluginConfigData := PluginConfigData{}
		actualPluginConfigData.Fill(api)
		assert.Equal(t, expectedPluginConfigData, actualPluginConfigData)
	})
}

func TestCircuitBreaker(t *testing.T) {
	t.Parallel()
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		var emptyCircuitBreaker CircuitBreaker

		var convertedCircuitBreaker apidef.CircuitBreakerMeta
		emptyCircuitBreaker.ExtractTo(&convertedCircuitBreaker)

		var resultCircuitBreaker CircuitBreaker
		resultCircuitBreaker.Fill(convertedCircuitBreaker)

		assert.Equal(t, emptyCircuitBreaker, resultCircuitBreaker)
	})

	t.Run("values", func(t *testing.T) {
		t.Parallel()
		expectedCircuitBreaker := CircuitBreaker{
			Enabled:              true,
			Threshold:            10,
			SampleSize:           5,
			CoolDownPeriod:       50,
			HalfOpenStateEnabled: true,
		}

		meta := apidef.CircuitBreakerMeta{}
		expectedCircuitBreaker.ExtractTo(&meta)

		actualCircuitBreaker := CircuitBreaker{}
		actualCircuitBreaker.Fill(meta)
		assert.Equal(t, expectedCircuitBreaker, actualCircuitBreaker)
	})
}

func TestVirtualEndpoint(t *testing.T) {
	t.Parallel()
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		var emptyVirtualEndpoint VirtualEndpoint

		var convertedVirtualEndpoint apidef.VirtualMeta
		emptyVirtualEndpoint.ExtractTo(&convertedVirtualEndpoint)

		var resultVirtualEndpoint VirtualEndpoint
		resultVirtualEndpoint.Fill(convertedVirtualEndpoint)

		assert.Equal(t, emptyVirtualEndpoint, resultVirtualEndpoint)
	})

	t.Run("blob", func(t *testing.T) {
		t.Parallel()
		expectedVirtualEndpoint := VirtualEndpoint{
			Enabled:        true,
			FunctionName:   "virtualFunc",
			Body:           "test body",
			ProxyOnError:   true,
			RequireSession: true,
		}

		meta := apidef.VirtualMeta{}
		expectedVirtualEndpoint.ExtractTo(&meta)

		// assert that FunctionSourceType is correctly updated.
		assert.Equal(t, apidef.VirtualMeta{
			Disabled:             false,
			FunctionSourceType:   apidef.UseBlob,
			FunctionSourceURI:    "test body",
			ResponseFunctionName: "virtualFunc",
			UseSession:           true,
			ProxyOnError:         true,
		}, meta)

		newVirtualEndpoint := VirtualEndpoint{}
		newVirtualEndpoint.Fill(meta)
		assert.Equal(t, expectedVirtualEndpoint, newVirtualEndpoint)
	})

	t.Run("path", func(t *testing.T) {
		t.Parallel()
		expectedVirtualEndpoint := VirtualEndpoint{
			Enabled:        true,
			FunctionName:   "virtualFunc",
			Path:           "/path/to/js",
			ProxyOnError:   true,
			RequireSession: true,
		}

		meta := apidef.VirtualMeta{}
		expectedVirtualEndpoint.ExtractTo(&meta)

		// assert that FunctionSourceType is correctly updated.
		assert.Equal(t, apidef.VirtualMeta{
			Disabled:             false,
			FunctionSourceType:   apidef.UseFile,
			FunctionSourceURI:    "/path/to/js",
			ResponseFunctionName: "virtualFunc",
			UseSession:           true,
			ProxyOnError:         true,
		}, meta)

		newVirtualEndpoint := VirtualEndpoint{}
		newVirtualEndpoint.Fill(meta)
		assert.Equal(t, expectedVirtualEndpoint, newVirtualEndpoint)
	})

	t.Run("blob should have precedence", func(t *testing.T) {
		t.Parallel()
		virtualEndpoint := VirtualEndpoint{
			Enabled:        true,
			Path:           "/path/to/js",
			Body:           "test body",
			FunctionName:   "virtualFunc",
			ProxyOnError:   true,
			RequireSession: true,
		}

		meta := apidef.VirtualMeta{}
		virtualEndpoint.ExtractTo(&meta)
		assert.Equal(t, apidef.VirtualMeta{
			Disabled:             false,
			ResponseFunctionName: "virtualFunc",
			FunctionSourceURI:    "test body",
			FunctionSourceType:   apidef.UseBlob,
			ProxyOnError:         true,
			UseSession:           true,
		}, meta)

		actualVirtualEndpoint := VirtualEndpoint{}
		actualVirtualEndpoint.Fill(meta)
		expectedVirtualEndpoint := virtualEndpoint
		expectedVirtualEndpoint.Path = ""
		assert.Equal(t, expectedVirtualEndpoint, actualVirtualEndpoint)
	})

	t.Run("functionName should have precedence", func(t *testing.T) {
		t.Parallel()
		virtualEndpoint := VirtualEndpoint{
			Enabled:        true,
			Path:           "/path/to/js",
			Body:           "test body",
			Name:           "virtualFunc",
			FunctionName:   "newVirtualFunc",
			ProxyOnError:   true,
			RequireSession: true,
		}

		meta := apidef.VirtualMeta{}
		virtualEndpoint.ExtractTo(&meta)
		assert.Equal(t, apidef.VirtualMeta{
			Disabled:             false,
			ResponseFunctionName: "newVirtualFunc",
			FunctionSourceURI:    "test body",
			FunctionSourceType:   apidef.UseBlob,
			ProxyOnError:         true,
			UseSession:           true,
		}, meta)

		actualVirtualEndpoint := VirtualEndpoint{}
		actualVirtualEndpoint.Fill(meta)
		expectedVirtualEndpoint := virtualEndpoint
		expectedVirtualEndpoint.Name = ""
		expectedVirtualEndpoint.Path = ""
		assert.Equal(t, expectedVirtualEndpoint, actualVirtualEndpoint)
	})

	t.Run("json", func(t *testing.T) {
		v := VirtualEndpoint{
			Enabled: true,
			Name:    "func",
		}
		body, err := json.Marshal(&v)
		assert.NoError(t, err)
		assert.Contains(t, string(body), "functionName")
		assert.NotContains(t, string(body), "name")
	})
}

func TestEndpointPostPlugins(t *testing.T) {
	t.Parallel()
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		var emptyPostPlugins EndpointPostPlugins

		var convertedGoPlugin apidef.GoPluginMeta
		emptyPostPlugins.ExtractTo(&convertedGoPlugin)

		var resultEmptyPostPlugins EndpointPostPlugins
		resultEmptyPostPlugins.Fill(convertedGoPlugin)

		assert.Equal(t, emptyPostPlugins, resultEmptyPostPlugins)
	})

	t.Run("single empty post plugin", func(t *testing.T) {
		t.Parallel()
		var emptyPostPlugins = make(EndpointPostPlugins, 1)

		var convertedGoPlugin apidef.GoPluginMeta
		emptyPostPlugins.ExtractTo(&convertedGoPlugin)

		var resultEmptyPostPlugins = make(EndpointPostPlugins, 1)
		resultEmptyPostPlugins.Fill(convertedGoPlugin)

		assert.Equal(t, emptyPostPlugins, resultEmptyPostPlugins)
	})

	t.Run("values", func(t *testing.T) {
		t.Parallel()
		expectedEndpointPostPlugins := EndpointPostPlugins{
			{
				Enabled:      true,
				FunctionName: "symbolFunc",
				Path:         "/path/to/so",
			},
		}

		meta := apidef.GoPluginMeta{}
		expectedEndpointPostPlugins.ExtractTo(&meta)

		actualEndpointPostPlugins := make(EndpointPostPlugins, 1)
		actualEndpointPostPlugins.Fill(meta)

		assert.Equal(t, expectedEndpointPostPlugins, actualEndpointPostPlugins)
	})

	t.Run("value - function name should have precedence", func(t *testing.T) {
		t.Parallel()
		endpointPostPlugin := EndpointPostPlugins{
			{
				Enabled:      true,
				Name:         "symbolFunc",
				FunctionName: "newSymbolFunc",
				Path:         "/path/to/so",
			},
		}

		meta := apidef.GoPluginMeta{}
		endpointPostPlugin.ExtractTo(&meta)

		actualEndpointPostPlugins := make(EndpointPostPlugins, 1)
		actualEndpointPostPlugins.Fill(meta)

		expectedEndpointPostPlugins := endpointPostPlugin
		expectedEndpointPostPlugins[0].Name = ""
		assert.Equal(t, expectedEndpointPostPlugins, actualEndpointPostPlugins)
	})

	t.Run("json", func(t *testing.T) {
		v := EndpointPostPlugin{
			Enabled: true,
			Name:    "func",
		}
		body, err := json.Marshal(&v)
		assert.NoError(t, err)
		assert.Contains(t, string(body), "functionName")
		assert.NotContains(t, string(body), "name")
	})
}

func TestTransformHeaders(t *testing.T) {
	var emptyTransformHeaders TransformHeaders

	var converted apidef.HeaderInjectionMeta
	emptyTransformHeaders.ExtractTo(&converted)

	var resultTransformHeaders TransformHeaders
	resultTransformHeaders.Fill(converted)

	assert.Equal(t, emptyTransformHeaders, resultTransformHeaders)
}

func TestContextVariables(t *testing.T) {
	t.Parallel()
	t.Run("fill", func(t *testing.T) {
		t.Parallel()
		testcases := []struct {
			title    string
			input    apidef.APIDefinition
			expected *ContextVariables
		}{
			{
				"enabled",
				apidef.APIDefinition{EnableContextVars: true},
				&ContextVariables{Enabled: true},
			},
			{
				"disabled",
				apidef.APIDefinition{EnableContextVars: false},
				nil,
			},
		}

		for _, tc := range testcases {
			tc := tc
			t.Run(tc.title, func(t *testing.T) {
				t.Parallel()

				g := new(Global)
				g.Fill(tc.input)

				assert.Equal(t, tc.expected, g.ContextVariables)
			})
		}
	})

	t.Run("extractTo", func(t *testing.T) {
		t.Parallel()

		testcases := []struct {
			title    string
			input    *ContextVariables
			expected bool
		}{
			{
				"enabled",
				&ContextVariables{Enabled: true},
				true,
			},
			{
				"disabled",
				nil,
				false,
			},
		}

		for _, tc := range testcases {
			tc := tc // Creating a new 'tc' scoped to the loop
			t.Run(tc.title, func(t *testing.T) {
				t.Parallel()

				g := new(Global)
				g.ContextVariables = tc.input

				var apiDef apidef.APIDefinition
				g.ExtractTo(&apiDef)

				assert.Equal(t, tc.expected, apiDef.EnableContextVars)
			})
		}
	})
}
