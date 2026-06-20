package oas

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: SYS-REQ-104, SW-REQ-089
// SW-REQ-089:nominal:nominal
// SW-REQ-089:boundary:nominal
// SW-REQ-089:boundary:boundary
// SW-REQ-089:error_handling:nominal
// SW-REQ-089:error_handling:negative
// SW-REQ-089:determinism:nominal
func TestMiddlewareReqProof_GlobalAggregateAndDeprecatedJSON(t *testing.T) {
	plugin := CustomPlugin{
		Enabled:        true,
		FunctionName:   "pluginFunc",
		Path:           "/plugins/plugin.so",
		RawBodyOnly:    true,
		RequireSession: true,
	}
	api := apidef.APIDefinition{
		ConfigDataDisabled:             false,
		ConfigData:                     map[string]interface{}{"region": "eu", "limit": float64(7)},
		CustomMiddlewareBundleDisabled: false,
		CustomMiddlewareBundle:         "bundle.zip",
		CustomMiddleware: apidef.MiddlewareSection{
			Driver:      apidef.GoPluginDriver,
			Pre:         []apidef.MiddlewareDefinition{{Disabled: false, Name: "pre", Path: "/plugins/pre.so", RawBodyOnly: true}},
			PostKeyAuth: []apidef.MiddlewareDefinition{{Disabled: false, Name: "postAuth", Path: "/plugins/post-auth.so", RequireSession: true}},
			Post:        []apidef.MiddlewareDefinition{{Disabled: false, Name: "post", Path: "/plugins/post.so"}},
			Response:    []apidef.MiddlewareDefinition{{Disabled: false, Name: "response", Path: "/plugins/response.so"}},
		},
		CORS: apidef.CORSConfig{
			Enable:             true,
			MaxAge:             60,
			AllowCredentials:   true,
			ExposedHeaders:     []string{"X-Expose"},
			AllowedHeaders:     []string{"Authorization"},
			OptionsPassthrough: true,
			Debug:              true,
			AllowedOrigins:     []string{"https://example.com"},
			AllowedMethods:     []string{http.MethodGet, http.MethodPost},
		},
		CacheOptions: apidef.CacheOptions{
			EnableCache:                true,
			CacheTimeout:               30,
			CacheAllSafeRequests:       true,
			CacheOnlyResponseCodes:     []int{200, 201},
			CacheByHeaders:             []string{"X-Tenant"},
			EnableUpstreamCacheControl: true,
			CacheControlTTLHeader:      "X-TTL",
		},
		VersionData: apidef.VersionData{Versions: map[string]apidef.VersionInfo{
			Main: {
				GlobalHeadersDisabled:         false,
				GlobalHeaders:                 map[string]string{"X-Request": "yes"},
				GlobalHeadersRemove:           []string{"X-Remove"},
				GlobalResponseHeadersDisabled: false,
				GlobalResponseHeaders:         map[string]string{"X-Response": "yes"},
				GlobalResponseHeadersRemove:   []string{"X-Response-Remove"},
				GlobalSizeLimit:               2048,
				GlobalSizeLimitDisabled:       false,
				IgnoreEndpointCase:            true,
			},
		}},
		EnableContextVars:     true,
		DoNotTrack:            false,
		TagHeaders:            []string{"X-Team"},
		ExpireAnalyticsAfter:  120,
		DisableRateLimit:      true,
		DisableQuota:          true,
		DontSetQuotasOnCreate: true,
		AnalyticsPlugin: apidef.AnalyticsPluginConfig{
			Enabled:    true,
			FuncName:   "analytics",
			PluginPath: "/plugins/analytics.so",
		},
	}

	var middleware Middleware
	middleware.Fill(api)

	require.NotNil(t, middleware.Global)
	require.NotNil(t, middleware.Global.PluginConfig)
	assert.Equal(t, apidef.GoPluginDriver, middleware.Global.PluginConfig.Driver)
	require.NotNil(t, middleware.Global.PluginConfig.Bundle)
	assert.True(t, middleware.Global.PluginConfig.Bundle.Enabled)
	assert.Equal(t, "bundle.zip", middleware.Global.PluginConfig.Bundle.Path)
	require.NotNil(t, middleware.Global.PluginConfig.Data)
	assert.True(t, middleware.Global.PluginConfig.Data.Enabled)
	assert.Equal(t, map[string]interface{}{"region": "eu", "limit": float64(7)}, middleware.Global.PluginConfig.Data.Value)
	require.NotNil(t, middleware.Global.CORS)
	assert.Equal(t, []string{"https://example.com"}, middleware.Global.CORS.AllowedOrigins)
	require.NotNil(t, middleware.Global.Cache)
	assert.True(t, middleware.Global.Cache.Enabled)
	assert.Equal(t, []int{200, 201}, middleware.Global.Cache.CacheResponseCodes)
	assert.Equal(t, CustomPlugins{{Enabled: true, FunctionName: "pre", Path: "/plugins/pre.so", RawBodyOnly: true}}, middleware.Global.PrePlugins)
	assert.Equal(t, CustomPlugins{{Enabled: true, FunctionName: "postAuth", Path: "/plugins/post-auth.so", RequireSession: true}}, middleware.Global.PostAuthenticationPlugins)
	assert.Equal(t, CustomPlugins{{Enabled: true, FunctionName: "post", Path: "/plugins/post.so"}}, middleware.Global.PostPlugins)
	assert.Equal(t, CustomPlugins{{Enabled: true, FunctionName: "response", Path: "/plugins/response.so"}}, middleware.Global.ResponsePlugins)
	require.NotNil(t, middleware.Global.TransformRequestHeaders)
	assert.Equal(t, Headers{{Name: "X-Request", Value: "yes"}}, middleware.Global.TransformRequestHeaders.Add)
	require.NotNil(t, middleware.Global.TransformResponseHeaders)
	assert.Equal(t, Headers{{Name: "X-Response", Value: "yes"}}, middleware.Global.TransformResponseHeaders.Add)
	require.NotNil(t, middleware.Global.ContextVariables)
	require.NotNil(t, middleware.Global.TrafficLogs)
	assert.Equal(t, ReadableDuration(120*time.Second), middleware.Global.TrafficLogs.CustomRetentionPeriod)
	assert.Equal(t, CustomAnalyticsPlugins{{Enabled: true, FunctionName: "analytics", Path: "/plugins/analytics.so"}}, middleware.Global.TrafficLogs.Plugins)
	require.NotNil(t, middleware.Global.RequestSizeLimit)
	assert.Equal(t, int64(2048), middleware.Global.RequestSizeLimit.Value)
	require.NotNil(t, middleware.Global.IgnoreCase)
	assert.True(t, middleware.Global.SkipRateLimit)
	assert.True(t, middleware.Global.SkipQuota)
	assert.True(t, middleware.Global.SkipQuotaReset)

	var extracted apidef.APIDefinition
	middleware.ExtractTo(&extracted)
	assert.Equal(t, apidef.GoPluginDriver, extracted.CustomMiddleware.Driver)
	assert.False(t, extracted.CustomMiddlewareBundleDisabled)
	assert.Equal(t, "bundle.zip", extracted.CustomMiddlewareBundle)
	assert.Equal(t, map[string]interface{}{"region": "eu", "limit": float64(7)}, extracted.ConfigData)
	assert.True(t, extracted.CORS.Enable)
	assert.True(t, extracted.CacheOptions.EnableCache)
	assert.Equal(t, "pre", extracted.CustomMiddleware.Pre[0].Name)
	assert.Equal(t, "postAuth", extracted.CustomMiddleware.PostKeyAuth[0].Name)
	assert.Equal(t, "post", extracted.CustomMiddleware.Post[0].Name)
	assert.Equal(t, "response", extracted.CustomMiddleware.Response[0].Name)
	assert.Equal(t, "yes", extracted.VersionData.Versions[Main].GlobalHeaders["X-Request"])
	assert.Equal(t, "yes", extracted.VersionData.Versions[Main].GlobalResponseHeaders["X-Response"])
	assert.Equal(t, int64(2048), extracted.VersionData.Versions[Main].GlobalSizeLimit)
	assert.True(t, extracted.VersionData.Versions[Main].IgnoreEndpointCase)
	assert.True(t, extracted.EnableContextVars)
	assert.False(t, extracted.DoNotTrack)
	assert.Equal(t, int64(120), extracted.ExpireAnalyticsAfter)
	assert.True(t, extracted.DisableRateLimit)
	assert.True(t, extracted.DisableQuota)
	assert.True(t, extracted.DontSetQuotasOnCreate)
	assert.True(t, extracted.AnalyticsPlugin.Enabled)

	deprecated := Global{
		PrePlugin:                &PrePlugin{Plugins: CustomPlugins{plugin}},
		PostAuthenticationPlugin: &PostAuthenticationPlugin{Plugins: CustomPlugins{plugin}},
		PostPlugin:               &PostPlugin{Plugins: CustomPlugins{plugin}},
		ResponsePlugin:           &ResponsePlugin{Plugins: CustomPlugins{plugin}},
	}
	body, err := json.Marshal(&deprecated)
	require.NoError(t, err)
	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &payload))
	assert.NotContains(t, payload, "prePlugin")
	assert.NotContains(t, payload, "postAuthenticationPlugin")
	assert.NotContains(t, payload, "postPlugin")
	assert.NotContains(t, payload, "responsePlugin")
	assert.Contains(t, payload, "prePlugins")
	assert.Contains(t, payload, "postAuthenticationPlugins")
	assert.Contains(t, payload, "postPlugins")
	assert.Contains(t, payload, "responsePlugins")

	empty := &Middleware{}
	var emptyExtracted apidef.APIDefinition
	require.NotPanics(t, func() {
		empty.ExtractTo(&emptyExtracted)
	})
	assert.Nil(t, empty.Global)
}

// Verifies: SYS-REQ-104, SW-REQ-089
// SW-REQ-089:nominal:nominal
// SW-REQ-089:boundary:boundary
// SW-REQ-089:error_handling:negative
// SW-REQ-089:determinism:nominal
func TestMiddlewareReqProof_PathsPluginsAndPrimitiveExtraction(t *testing.T) {
	ep := apidef.ExtendedPathsSet{
		WhiteList:          []apidef.EndPointMeta{{Path: "/pets", Method: http.MethodGet, IgnoreCase: true}},
		BlackList:          []apidef.EndPointMeta{{Path: "/pets", Method: http.MethodPost}},
		Ignored:            []apidef.EndPointMeta{{Path: "/pets", Method: http.MethodPut}},
		MethodTransforms:   []apidef.MethodTransformMeta{{Path: "/pets", Method: http.MethodPatch, ToMethod: http.MethodPost}},
		AdvanceCacheConfig: []apidef.CacheMeta{{Path: "/pets", Method: http.MethodHead, Disabled: false, CacheKeyRegex: "id=(\\d+)", CacheOnlyResponseCodes: []int{200}}},
		HardTimeouts:       []apidef.HardTimeoutMeta{{Path: "/pets", Method: http.MethodOptions, TimeOut: 7}},
	}

	paths := Paths{}
	paths.Fill(ep)

	require.NotNil(t, paths["/pets"].Get.Allow)
	assert.True(t, paths["/pets"].Get.Allow.Enabled)
	assert.True(t, paths["/pets"].Get.Allow.IgnoreCase)
	require.NotNil(t, paths["/pets"].Post.Block)
	require.NotNil(t, paths["/pets"].Put.IgnoreAuthentication)
	require.NotNil(t, paths["/pets"].Patch.TransformRequestMethod)
	assert.Equal(t, http.MethodPost, paths["/pets"].Patch.TransformRequestMethod.ToMethod)
	require.NotNil(t, paths["/pets"].Head.Cache)
	assert.Equal(t, apidef.DefaultCacheTimeout, paths["/pets"].Head.Cache.Timeout)
	require.NotNil(t, paths["/pets"].Options.EnforceTimeout)
	assert.Equal(t, 7, paths["/pets"].Options.EnforceTimeout.Value)

	var extracted apidef.ExtendedPathsSet
	paths.ExtractTo(&extracted)
	assert.Len(t, extracted.WhiteList, 1)
	assert.Len(t, extracted.BlackList, 1)
	assert.Len(t, extracted.Ignored, 1)
	assert.Len(t, extracted.MethodTransforms, 1)
	assert.Len(t, extracted.AdvanceCacheConfig, 1)
	assert.Len(t, extracted.HardTimeouts, 1)
	assert.Equal(t, "/pets", extracted.WhiteList[0].Path)
	assert.Equal(t, http.MethodGet, extracted.WhiteList[0].Method)
	assert.Equal(t, "id=(\\d+)", extracted.AdvanceCacheConfig[0].CacheKeyRegex)

	methodCases := []struct {
		name   string
		method string
		got    func(*Path) **Plugins
	}{
		{name: "GET", method: http.MethodGet, got: func(p *Path) **Plugins { return &p.Get }},
		{name: "POST", method: http.MethodPost, got: func(p *Path) **Plugins { return &p.Post }},
		{name: "PUT", method: http.MethodPut, got: func(p *Path) **Plugins { return &p.Put }},
		{name: "DELETE", method: http.MethodDelete, got: func(p *Path) **Plugins { return &p.Delete }},
		{name: "HEAD", method: http.MethodHead, got: func(p *Path) **Plugins { return &p.Head }},
		{name: "OPTIONS", method: http.MethodOptions, got: func(p *Path) **Plugins { return &p.Options }},
		{name: "TRACE", method: http.MethodTrace, got: func(p *Path) **Plugins { return &p.Trace }},
		{name: "PATCH", method: http.MethodPatch, got: func(p *Path) **Plugins { return &p.Patch }},
		{name: "CONNECT", method: http.MethodConnect, got: func(p *Path) **Plugins { return &p.Connect }},
		{name: "unknown defaults to GET", method: "UNKNOWN", got: func(p *Path) **Plugins { return &p.Get }},
	}

	for _, tc := range methodCases {
		t.Run("method "+tc.name, func(t *testing.T) {
			var p Path
			assert.Same(t, p.getMethod(tc.method), *tc.got(&p))
		})
	}

	middleware := &Middleware{
		McpTools: MCPPrimitives{
			"weather": {Operation: Operation{
				MockResponse:     &MockResponse{Enabled: true},
				Allow:            &Allowance{Enabled: true},
				RequestSizeLimit: &RequestSizeLimit{Enabled: true, Value: 1024},
				TransformRequestHeaders: &TransformHeaders{Enabled: true, Add: Headers{
					{Name: "X-Tool", Value: "weather"},
				}},
			}},
		},
		McpResources: MCPPrimitives{"repo": {Operation: Operation{Allow: &Allowance{Enabled: true}}}},
		McpPrompts:   MCPPrimitives{"review": nil},
	}
	assert.True(t, middleware.HasMCPPrimitivesMocks())
	assert.True(t, hasMockInPrimitives(middleware.McpTools))

	var primitiveEP apidef.ExtendedPathsSet
	middleware.ExtractPrimitivesToExtendedPaths(&primitiveEP)
	require.Len(t, primitiveEP.Internal, 2)
	assert.ElementsMatch(t, []string{"/mcp-resource:repo", "/mcp-tool:weather"}, []string{primitiveEP.Internal[0].Path, primitiveEP.Internal[1].Path})
	assert.Len(t, primitiveEP.WhiteList, 2)
	assert.Len(t, primitiveEP.SizeLimit, 1)
	assert.Len(t, primitiveEP.TransformHeader, 1)
	assert.Empty(t, primitiveEP.MockResponse)
}

// Verifies: SYS-REQ-104, SW-REQ-089
// SW-REQ-089:nominal:nominal
// SW-REQ-089:boundary:boundary
// SW-REQ-089:error_handling:negative
// SW-REQ-089:determinism:nominal
func TestMiddlewareReqProof_ScalarAndPluginHelpers(t *testing.T) {
	scalarCases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "allowance",
			run: func(t *testing.T) {
				allowance := Allowance{Enabled: true, IgnoreCase: true}
				endpoint := apidef.EndPointMeta{}
				allowance.ExtractTo(&endpoint)
				assert.False(t, endpoint.Disabled)
				assert.True(t, endpoint.IgnoreCase)
				var filledAllowance Allowance
				filledAllowance.Fill(endpoint)
				assert.Equal(t, allowance, filledAllowance)
				filledAllowance.Import(false)
				assert.False(t, filledAllowance.Enabled)
			},
		},
		{
			name: "method transform",
			run: func(t *testing.T) {
				method := TransformRequestMethod{Enabled: true, ToMethod: http.MethodPost}
				methodMeta := apidef.MethodTransformMeta{}
				method.ExtractTo(&methodMeta)
				assert.False(t, methodMeta.Disabled)
				assert.Equal(t, http.MethodPost, methodMeta.ToMethod)
			},
		},
		{
			name: "body transform",
			run: func(t *testing.T) {
				body := TransformBody{Enabled: true, Path: "/template.tmpl", Body: "encoded", Format: apidef.RequestJSON}
				var bodyMeta apidef.TemplateMeta
				body.ExtractTo(&bodyMeta)
				assert.Equal(t, apidef.UseBlob, bodyMeta.TemplateData.Mode)
				assert.Equal(t, "encoded", bodyMeta.TemplateData.TemplateSource)
				var filledBody TransformBody
				filledBody.Fill(bodyMeta)
				assert.Equal(t, TransformBody{Enabled: true, Body: "encoded", Format: apidef.RequestJSON}, filledBody)
			},
		},
		{
			name: "header transform",
			run: func(t *testing.T) {
				headers := TransformHeaders{Enabled: true, Remove: []string{"X-Remove"}}
				headers.AppendAddOp("X-Add", "value")
				var headerMeta apidef.HeaderInjectionMeta
				headers.ExtractTo(&headerMeta)
				assert.False(t, headerMeta.Disabled)
				assert.Equal(t, []string{"X-Remove"}, headerMeta.DeleteHeaders)
				assert.Equal(t, "value", headerMeta.AddHeaders["X-Add"])
				var filledHeaders TransformHeaders
				filledHeaders.Fill(headerMeta)
				assert.Equal(t, headers, filledHeaders)
			},
		},
		{
			name: "cache default timeout",
			run: func(t *testing.T) {
				cache := CachePlugin{Enabled: true}
				cache.Fill(apidef.CacheMeta{Disabled: false})
				assert.Equal(t, apidef.DefaultCacheTimeout, cache.Timeout)
				var cacheMeta apidef.CacheMeta
				cache.ExtractTo(&cacheMeta)
				assert.False(t, cacheMeta.Disabled)
			},
		},
		{
			name: "enforced timeout",
			run: func(t *testing.T) {
				timeout := EnforceTimeout{Enabled: true, Value: 9}
				var timeoutMeta apidef.HardTimeoutMeta
				timeout.ExtractTo(&timeoutMeta)
				assert.Equal(t, 9, timeoutMeta.TimeOut)
			},
		},
	}

	for _, tc := range scalarCases {
		t.Run(tc.name, tc.run)
	}

	plugins := CustomPlugins{{Enabled: true, FunctionName: "fn", Path: "/plugin.so", RawBodyOnly: true, RequireSession: true}}
	mwDefs := make([]apidef.MiddlewareDefinition, 1)
	plugins.ExtractTo(mwDefs)
	assert.Equal(t, "fn", mwDefs[0].Name)
	var filledPlugins CustomPlugins
	filledPlugins.Fill(mwDefs)
	assert.Equal(t, plugins, filledPlugins)
	var nilPlugins *CustomPlugins
	require.NotPanics(t, func() {
		nilPlugins.ExtractTo(nil)
	})

	api := apidef.APIDefinition{}
	(&PrePlugin{Plugins: plugins}).ExtractTo(&api)
	(&PostAuthenticationPlugin{Plugins: plugins}).ExtractTo(&api)
	(&PostPlugin{Plugins: plugins}).ExtractTo(&api)
	(&ResponsePlugin{Plugins: plugins}).ExtractTo(&api)
	assert.Equal(t, "fn", api.CustomMiddleware.Pre[0].Name)
	assert.Equal(t, "fn", api.CustomMiddleware.PostKeyAuth[0].Name)
	assert.Equal(t, "fn", api.CustomMiddleware.Post[0].Name)
	assert.Equal(t, "fn", api.CustomMiddleware.Response[0].Name)

	var pre PrePlugin
	var postAuth PostAuthenticationPlugin
	var post PostPlugin
	var response ResponsePlugin
	pre.Fill(api)
	postAuth.Fill(api)
	post.Fill(api)
	response.Fill(api)
	assert.Equal(t, plugins, pre.Plugins)
	assert.Equal(t, plugins, postAuth.Plugins)
	assert.Equal(t, plugins, post.Plugins)
	assert.Equal(t, plugins, response.Plugins)
}

// Verifies: SYS-REQ-104, SW-REQ-089
// SW-REQ-089:nominal:nominal
// SW-REQ-089:boundary:boundary
// SW-REQ-089:error_handling:negative
// SW-REQ-089:determinism:nominal
func TestMiddlewareReqProof_EndpointVirtualAnalyticsAndLimits(t *testing.T) {
	legacyVirtual := VirtualEndpoint{Enabled: true, Name: "legacyName"}
	body, err := json.Marshal(&legacyVirtual)
	require.NoError(t, err)
	var virtualPayload map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &virtualPayload))
	assert.NotContains(t, virtualPayload, "name")
	assert.Equal(t, "legacyName", virtualPayload["functionName"])

	virtual := VirtualEndpoint{Enabled: true, Name: "legacyName", FunctionName: "newName", Path: "/virtual.js", Body: "encoded", ProxyOnError: true, RequireSession: true}
	var virtualMeta apidef.VirtualMeta
	virtual.ExtractTo(&virtualMeta)
	assert.Equal(t, "newName", virtualMeta.ResponseFunctionName)
	assert.Equal(t, apidef.UseBlob, virtualMeta.FunctionSourceType)
	assert.Equal(t, "encoded", virtualMeta.FunctionSourceURI)
	var filledVirtual VirtualEndpoint
	filledVirtual.Fill(virtualMeta)
	assert.Equal(t, VirtualEndpoint{Enabled: true, FunctionName: "newName", Body: "encoded", ProxyOnError: true, RequireSession: true}, filledVirtual)

	legacyEndpointPlugin := EndpointPostPlugin{Enabled: true, Name: "legacy", Path: "/post.so"}
	body, err = json.Marshal(&legacyEndpointPlugin)
	require.NoError(t, err)
	var endpointPayload map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &endpointPayload))
	assert.NotContains(t, endpointPayload, "name")
	assert.Equal(t, "legacy", endpointPayload["functionName"])

	endpointPlugin := EndpointPostPlugins{{Enabled: true, Name: "legacy", FunctionName: "symbol", Path: "/post.so"}}
	var goPlugin apidef.GoPluginMeta
	endpointPlugin.ExtractTo(&goPlugin)
	assert.Equal(t, "symbol", goPlugin.SymbolName)
	var filledEndpointPlugins = make(EndpointPostPlugins, 1)
	filledEndpointPlugins.Fill(goPlugin)
	assert.Equal(t, EndpointPostPlugins{{Enabled: true, FunctionName: "symbol", Path: "/post.so"}}, filledEndpointPlugins)

	circuitBreaker := CircuitBreaker{Enabled: true, Threshold: 0.4, SampleSize: 10, CoolDownPeriod: 20, HalfOpenStateEnabled: true}
	var circuitMeta apidef.CircuitBreakerMeta
	circuitBreaker.ExtractTo(&circuitMeta)
	assert.False(t, circuitMeta.Disabled)
	assert.Equal(t, int64(10), circuitMeta.Samples)
	var filledCircuit CircuitBreaker
	filledCircuit.Fill(circuitMeta)
	assert.Equal(t, circuitBreaker, filledCircuit)

	requestSize := RequestSizeLimit{Enabled: true, Value: 4096}
	var requestSizeMeta apidef.RequestSizeMeta
	requestSize.ExtractTo(&requestSizeMeta)
	assert.False(t, requestSizeMeta.Disabled)
	assert.Equal(t, int64(4096), requestSizeMeta.SizeLimit)

	var api apidef.APIDefinition
	traffic := TrafficLogs{
		Enabled:               true,
		TagHeaders:            []string{"X-Team"},
		CustomRetentionPeriod: ReadableDuration(2*time.Minute + 50*time.Millisecond),
		Plugins:               CustomAnalyticsPlugins{{Enabled: true, FunctionName: "analytics", Path: "/analytics.so"}},
	}
	traffic.ExtractTo(&api)
	assert.False(t, api.DoNotTrack)
	assert.Equal(t, int64(120), api.ExpireAnalyticsAfter)
	assert.True(t, api.AnalyticsPlugin.Enabled)
	var filledTraffic TrafficLogs
	filledTraffic.Fill(api)
	assert.Equal(t, ReadableDuration(2*time.Minute), filledTraffic.CustomRetentionPeriod)
	assert.Equal(t, traffic.Plugins, filledTraffic.Plugins)

	globalLimit := GlobalRequestSizeLimit{Enabled: false, Value: 5000}
	globalLimit.ExtractTo(&api)
	assert.True(t, api.VersionData.Versions[Main].GlobalSizeLimitDisabled)
	assert.Equal(t, int64(5000), api.VersionData.Versions[Main].GlobalSizeLimit)
	var filledLimit GlobalRequestSizeLimit
	filledLimit.Fill(api)
	assert.Equal(t, globalLimit, filledLimit)

	contextVariables := ContextVariables{Enabled: true}
	contextVariables.ExtractTo(&api)
	assert.True(t, api.EnableContextVars)
	var filledContext ContextVariables
	filledContext.Fill(api)
	assert.Equal(t, contextVariables, filledContext)

	ignoreCase := IgnoreCase{Enabled: true}
	ignoreCase.ExtractTo(&api)
	assert.True(t, api.VersionData.Versions[Main].IgnoreEndpointCase)
	var filledIgnoreCase IgnoreCase
	filledIgnoreCase.Fill(api)
	assert.Equal(t, ignoreCase, filledIgnoreCase)
}
