package oas

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
)

// Middleware holds configuration for Tyk's native middleware.
type Middleware struct {
	// Global contains configuration for middleware that affects the whole API (all endpoints).
	Global *Global `bson:"global,omitempty" json:"global,omitempty"`

	// Operations contains configuration for middleware that can be applied to individual endpoints within the API (per-endpoint).
	Operations Operations `bson:"operations,omitempty" json:"operations,omitempty"`

	// McpTools contains configuration for middleware that can be applied to MCP tools.
	McpTools MCPPrimitives `bson:"mcpTools,omitempty" json:"mcpTools,omitempty"`

	// McpResources contains configuration for middleware that can be applied to MCP resources.
	McpResources MCPPrimitives `bson:"mcpResources,omitempty" json:"mcpResources,omitempty"`

	// McpPrompts contains configuration for middleware that can be applied to MCP prompts.
	McpPrompts MCPPrimitives `bson:"mcpPrompts,omitempty" json:"mcpPrompts,omitempty"`

	// McpOperations contains configuration for middleware that can be applied to MCP operations
	// (e.g., tools/list, resources/list, prompts/list, initialize, ping).
	McpOperations MCPPrimitives `bson:"mcpOperations,omitempty" json:"mcpOperations,omitempty"`
}

// Fill fills *Middleware from apidef.APIDefinition.
func (m *Middleware) Fill(api apidef.APIDefinition) {
	if m.Global == nil {
		m.Global = &Global{}
	}

	m.Global.Fill(api)
	if ShouldOmit(m.Global) {
		m.Global = nil
	}
}

// ExtractTo extracts *Middleware into *apidef.APIDefinition.
func (m *Middleware) ExtractTo(api *apidef.APIDefinition) {
	if m.Global == nil {
		m.Global = &Global{}
		defer func() {
			m.Global = nil
		}()
	}

	m.Global.ExtractTo(api)

	if len(m.McpTools) > 0 || len(m.McpResources) > 0 || len(m.McpPrompts) > 0 || len(m.McpOperations) > 0 {
		api.MarkAsMCP()
	}
}

// Global contains configuration that affects the whole API (all endpoints).
type Global struct {
	// PluginConfig contains the common configuration for custom plugins.
	PluginConfig *PluginConfig `bson:"pluginConfig,omitempty" json:"pluginConfig,omitempty"`

	// CORS contains the configuration related to Cross Origin Resource Sharing.
	// Tyk classic API definition: `CORS`.
	CORS *CORS `bson:"cors,omitempty" json:"cors,omitempty"`

	// PrePlugin contains configuration related to the custom plugin that is run before authentication.
	// Deprecated: Use PrePlugins instead.
	PrePlugin *PrePlugin `bson:"prePlugin,omitempty" json:"prePlugin,omitempty"`

	// PrePlugins contains configuration related to the custom plugin that is run before authentication.
	// Tyk classic API definition: `custom_middleware.pre`.
	PrePlugins CustomPlugins `bson:"prePlugins,omitempty" json:"prePlugins,omitempty"`

	// PostAuthenticationPlugin contains configuration related to the custom plugin that is run immediately after authentication.
	// Deprecated: Use PostAuthenticationPlugins instead.
	PostAuthenticationPlugin *PostAuthenticationPlugin `bson:"postAuthenticationPlugin,omitempty" json:"postAuthenticationPlugin,omitempty"`

	// PostAuthenticationPlugins contains configuration related to the custom plugin that is run immediately after authentication.
	// Tyk classic API definition: `custom_middleware.post_key_auth`.
	PostAuthenticationPlugins CustomPlugins `bson:"postAuthenticationPlugins,omitempty" json:"postAuthenticationPlugins,omitempty"`

	// PostPlugin contains configuration related to the custom plugin that is run immediately prior to proxying the request to the upstream.
	// Deprecated: Use PostPlugins instead.
	PostPlugin *PostPlugin `bson:"postPlugin,omitempty" json:"postPlugin,omitempty"`

	// PostPlugins contains configuration related to the custom plugin that is run immediately prior to proxying the request to the upstream.
	// Tyk classic API definition: `custom_middleware.post`.
	PostPlugins CustomPlugins `bson:"postPlugins,omitempty" json:"postPlugins,omitempty"`

	// ResponsePlugin contains configuration related to the custom plugin that is run during processing of the response from the upstream service.
	// Deprecated: Use ResponsePlugins instead.
	ResponsePlugin *ResponsePlugin `bson:"responsePlugin,omitempty" json:"responsePlugin,omitempty"`

	// ResponsePlugins contains configuration related to the custom plugin that is run during processing of the response from the upstream service.
	//
	// Tyk classic API definition: `custom_middleware.response`.
	ResponsePlugins CustomPlugins `bson:"responsePlugins,omitempty" json:"responsePlugins,omitempty"`

	// Cache contains the configurations related to caching.
	// Tyk classic API definition: `cache_options`.
	Cache *Cache `bson:"cache,omitempty" json:"cache,omitempty"`

	// TransformRequestHeaders contains the configurations related to API level request header transformation.
	// Tyk classic API definition: `global_headers`/`global_headers_remove`.
	TransformRequestHeaders *TransformHeaders `bson:"transformRequestHeaders,omitempty" json:"transformRequestHeaders,omitempty"`

	// TransformResponseHeaders contains the configurations related to API level response header transformation.
	// Tyk classic API definition: `global_response_headers`/`global_response_headers_remove`.
	TransformResponseHeaders *TransformHeaders `bson:"transformResponseHeaders,omitempty" json:"transformResponseHeaders,omitempty"`

	// ContextVariables contains the configuration related to Tyk context variables.
	ContextVariables *ContextVariables `bson:"contextVariables,omitempty" json:"contextVariables,omitempty"`

	// TrafficLogs contains the configurations related to API level log analytics.
	TrafficLogs *TrafficLogs `bson:"trafficLogs,omitempty" json:"trafficLogs,omitempty"`

	// RequestSizeLimit contains the configuration related to limiting the global request size.
	RequestSizeLimit *GlobalRequestSizeLimit `bson:"requestSizeLimit,omitempty" json:"requestSizeLimit,omitempty"`

	// IgnoreCase contains the configuration to treat routes as case-insensitive.
	IgnoreCase *IgnoreCase `bson:"ignoreCase,omitempty" json:"ignoreCase,omitempty"`

	// SkipRateLimit determines whether the rate-limiting middleware logic should be skipped.
	// Tyk classic API definition: `disable_rate_limit`.
	SkipRateLimit bool `bson:"skipRateLimit,omitempty" json:"skipRateLimit,omitempty"`

	// SkipQuota determines whether quota enforcement should be bypassed.
	// Tyk classic API definition: `disable_quota`.
	SkipQuota bool `bson:"skipQuota,omitempty" json:"skipQuota,omitempty"`

	// SkipQuotaReset indicates if quota limits should not be reset when creating or updating quotas for the API.
	// Tyk classic API definition: `dont_set_quota_on_create`.
	SkipQuotaReset bool `bson:"skipQuotaReset,omitempty" json:"skipQuotaReset,omitempty"`
}

// MarshalJSON is a custom JSON marshaller for the Global struct. It is implemented
// to facilitate a smooth migration from deprecated fields that were previously used to represent
// the same data. This custom marshaller ensures backwards compatibility and proper handling of the
// deprecated fields during the migration process.
func (g *Global) MarshalJSON() ([]byte, error) {
	if g == nil {
		return nil, nil
	}

	type Alias Global

	var payload = Alias(*g)

	if payload.PrePlugin != nil {
		payload.PrePlugins = payload.PrePlugin.Plugins
		payload.PrePlugin = nil
	}

	if payload.PostAuthenticationPlugin != nil {
		payload.PostAuthenticationPlugins = payload.PostAuthenticationPlugin.Plugins
		payload.PostAuthenticationPlugin = nil
	}

	if payload.PostPlugin != nil {
		payload.PostPlugins = payload.PostPlugin.Plugins
		payload.PostPlugin = nil
	}

	if payload.ResponsePlugin != nil {
		payload.ResponsePlugins = payload.ResponsePlugin.Plugins
		payload.ResponsePlugin = nil
	}

	// to prevent infinite recursion
	return json.Marshal(payload)
}

// Fill fills *Global from apidef.APIDefinition.
func (g *Global) Fill(api apidef.APIDefinition) {
	if g.PluginConfig == nil {
		g.PluginConfig = &PluginConfig{}
	}

	g.PluginConfig.Fill(api)
	if ShouldOmit(g.PluginConfig) {
		g.PluginConfig = nil
	}

	if g.CORS == nil {
		g.CORS = &CORS{}
	}

	g.CORS.Fill(api.CORS)
	if ShouldOmit(g.CORS) {
		g.CORS = nil
	}

	g.PrePlugins.Fill(api.CustomMiddleware.Pre)
	g.PrePlugin = nil

	if ShouldOmit(g.PrePlugins) {
		g.PrePlugins = nil
	}

	g.PostAuthenticationPlugins.Fill(api.CustomMiddleware.PostKeyAuth)
	g.PostAuthenticationPlugin = nil

	if ShouldOmit(g.PostAuthenticationPlugins) {
		g.PostAuthenticationPlugins = nil
	}

	g.PostPlugins.Fill(api.CustomMiddleware.Post)
	g.PostPlugin = nil

	if ShouldOmit(g.PostPlugins) {
		g.PostPlugins = nil
	}

	if g.Cache == nil {
		g.Cache = &Cache{}
	}

	g.Cache.Fill(api.CacheOptions)
	if ShouldOmit(g.Cache) {
		g.Cache = nil
	}

	g.ResponsePlugins.Fill(api.CustomMiddleware.Response)
	g.ResponsePlugin = nil

	if ShouldOmit(g.ResponsePlugins) {
		g.ResponsePlugins = nil
	}

	if g.TransformRequestHeaders == nil {
		g.TransformRequestHeaders = &TransformHeaders{}
	}

	vInfo := api.VersionData.Versions[Main]
	g.TransformRequestHeaders.Fill(apidef.HeaderInjectionMeta{
		Disabled:      vInfo.GlobalHeadersDisabled,
		AddHeaders:    vInfo.GlobalHeaders,
		DeleteHeaders: vInfo.GlobalHeadersRemove,
	})
	if ShouldOmit(g.TransformRequestHeaders) {
		g.TransformRequestHeaders = nil
	}

	if g.TransformResponseHeaders == nil {
		g.TransformResponseHeaders = &TransformHeaders{}
	}

	g.TransformResponseHeaders.Fill(apidef.HeaderInjectionMeta{
		Disabled:      vInfo.GlobalResponseHeadersDisabled,
		AddHeaders:    vInfo.GlobalResponseHeaders,
		DeleteHeaders: vInfo.GlobalResponseHeadersRemove,
	})
	if ShouldOmit(g.TransformResponseHeaders) {
		g.TransformResponseHeaders = nil
	}

	g.fillIgnoreCase(api)

	g.fillContextVariables(api)

	g.fillTrafficLogs(api)

	g.fillRequestSizeLimit(api)

	g.fillSkips(api)
}

func (g *Global) fillTrafficLogs(api apidef.APIDefinition) {
	if g.TrafficLogs == nil {
		g.TrafficLogs = &TrafficLogs{}
	}

	g.TrafficLogs.Fill(api)
	if ShouldOmit(g.TrafficLogs) {
		g.TrafficLogs = nil
	}
}

func (g *Global) fillRequestSizeLimit(api apidef.APIDefinition) {
	if g.RequestSizeLimit == nil {
		g.RequestSizeLimit = &GlobalRequestSizeLimit{}
	}

	g.RequestSizeLimit.Fill(api)
	if ShouldOmit(g.RequestSizeLimit) {
		g.RequestSizeLimit = nil
	}
}

func (g *Global) fillContextVariables(api apidef.APIDefinition) {
	if g.ContextVariables == nil {
		g.ContextVariables = &ContextVariables{}
	}

	g.ContextVariables.Fill(api)
	if ShouldOmit(g.ContextVariables) {
		g.ContextVariables = nil
	}
}

func (g *Global) fillSkips(api apidef.APIDefinition) {
	g.SkipRateLimit = api.DisableRateLimit
	g.SkipQuota = api.DisableQuota
	g.SkipQuotaReset = api.DontSetQuotasOnCreate
}

// ExtractTo extracts *Global into *apidef.APIDefinition.
func (g *Global) ExtractTo(api *apidef.APIDefinition) {
	if g.PluginConfig == nil {
		g.PluginConfig = &PluginConfig{}
		defer func() {
			g.PluginConfig = nil
		}()
	}

	g.PluginConfig.ExtractTo(api)

	if g.CORS == nil {
		g.CORS = &CORS{}
		defer func() {
			g.CORS = nil
		}()
	}

	g.CORS.ExtractTo(&api.CORS)

	g.extractPrePluginsTo(api)

	g.extractPostAuthenticationPluginsTo(api)

	g.extractPostPluginsTo(api)

	if g.Cache == nil {
		g.Cache = &Cache{}
		defer func() {
			g.Cache = nil
		}()
	}

	g.Cache.ExtractTo(&api.CacheOptions)

	g.extractResponsePluginsTo(api)

	g.extractIgnoreCase(api)

	g.extractContextVariablesTo(api)

	g.extractTrafficLogsTo(api)

	if g.TransformRequestHeaders == nil {
		g.TransformRequestHeaders = &TransformHeaders{}
		defer func() {
			g.TransformRequestHeaders = nil
		}()
	}

	var headerMeta apidef.HeaderInjectionMeta
	g.TransformRequestHeaders.ExtractTo(&headerMeta)

	if g.TransformResponseHeaders == nil {
		g.TransformResponseHeaders = &TransformHeaders{}
		defer func() {
			g.TransformResponseHeaders = nil
		}()
	}

	var resHeaderMeta apidef.HeaderInjectionMeta
	g.TransformResponseHeaders.ExtractTo(&resHeaderMeta)

	requireMainVersion(api)
	vInfo := api.VersionData.Versions[Main]
	vInfo.GlobalHeadersDisabled = headerMeta.Disabled
	vInfo.GlobalHeaders = headerMeta.AddHeaders
	vInfo.GlobalHeadersRemove = headerMeta.DeleteHeaders

	vInfo.GlobalResponseHeadersDisabled = resHeaderMeta.Disabled
	vInfo.GlobalResponseHeaders = resHeaderMeta.AddHeaders
	vInfo.GlobalResponseHeadersRemove = resHeaderMeta.DeleteHeaders
	updateMainVersion(api, vInfo)

	g.extractRequestSizeLimitTo(api)

	g.extractSkipsTo(api)
}

func (g *Global) extractTrafficLogsTo(api *apidef.APIDefinition) {
	if g.TrafficLogs == nil {
		g.TrafficLogs = &TrafficLogs{}
		defer func() {
			g.TrafficLogs = nil
		}()
	}

	g.TrafficLogs.ExtractTo(api)
}

func (g *Global) extractRequestSizeLimitTo(api *apidef.APIDefinition) {
	if g.RequestSizeLimit == nil {
		g.RequestSizeLimit = &GlobalRequestSizeLimit{}
		defer func() {
			g.RequestSizeLimit = nil
		}()
	}

	g.RequestSizeLimit.ExtractTo(api)
}

func (g *Global) extractContextVariablesTo(api *apidef.APIDefinition) {
	if g.ContextVariables == nil {
		g.ContextVariables = &ContextVariables{}
		defer func() {
			g.ContextVariables = nil
		}()
	}

	g.ContextVariables.ExtractTo(api)
}

func (g *Global) extractPrePluginsTo(api *apidef.APIDefinition) {
	defer func() {
		g.PrePlugin = nil
	}()

	// give precedence to PrePlugins over PrePlugin
	if g.PrePlugins != nil {
		api.CustomMiddleware.Pre = make([]apidef.MiddlewareDefinition, len(g.PrePlugins))
		g.PrePlugins.ExtractTo(api.CustomMiddleware.Pre)
		return
	}

	if g.PrePlugin == nil {
		g.PrePlugin = &PrePlugin{}
	}

	g.PrePlugin.ExtractTo(api)
}

func (g *Global) extractPostAuthenticationPluginsTo(api *apidef.APIDefinition) {
	defer func() {
		g.PostAuthenticationPlugin = nil
	}()

	if g.PostAuthenticationPlugins != nil {
		api.CustomMiddleware.PostKeyAuth = make([]apidef.MiddlewareDefinition, len(g.PostAuthenticationPlugins))
		g.PostAuthenticationPlugins.ExtractTo(api.CustomMiddleware.PostKeyAuth)
		return
	}

	if g.PostAuthenticationPlugin == nil {
		g.PostAuthenticationPlugin = &PostAuthenticationPlugin{}
	}

	g.PostAuthenticationPlugin.ExtractTo(api)
}

func (g *Global) extractPostPluginsTo(api *apidef.APIDefinition) {
	defer func() {
		g.PostPlugin = nil
	}()

	if g.PostPlugins != nil {
		api.CustomMiddleware.Post = make([]apidef.MiddlewareDefinition, len(g.PostPlugins))
		g.PostPlugins.ExtractTo(api.CustomMiddleware.Post)
		return
	}

	if g.PostPlugin == nil {
		g.PostPlugin = &PostPlugin{}
	}

	g.PostPlugin.ExtractTo(api)
}

func (g *Global) extractResponsePluginsTo(api *apidef.APIDefinition) {
	defer func() {
		g.ResponsePlugin = nil
	}()

	if g.ResponsePlugins != nil {
		api.CustomMiddleware.Response = make([]apidef.MiddlewareDefinition, len(g.ResponsePlugins))
		g.ResponsePlugins.ExtractTo(api.CustomMiddleware.Response)
		return
	}

	if g.ResponsePlugin == nil {
		g.ResponsePlugin = &ResponsePlugin{}
	}

	g.ResponsePlugin.ExtractTo(api)
}

func (g *Global) extractSkipsTo(api *apidef.APIDefinition) {
	api.DisableRateLimit = g.SkipRateLimit
	api.DisableQuota = g.SkipQuota
	api.DontSetQuotasOnCreate = g.SkipQuotaReset
}

// PluginConfigData configures config data for custom plugins.
type PluginConfigData struct {
	// Enabled activates custom plugin config data.
	//
	// Tyk classic API definition: `config_data_disabled` (negated).
	Enabled bool `bson:"enabled" json:"enabled"` // required.

	// Value is the value of custom plugin config data.
	//
	// Tyk classic API definition: `config_data`.
	Value map[string]interface{} `bson:"value" json:"value"` // required.
}

// Fill fills PluginConfigData from apidef.
func (p *PluginConfigData) Fill(api apidef.APIDefinition) {
	p.Enabled = !api.ConfigDataDisabled
	p.Value = api.ConfigData
}

// ExtractTo extracts *PluginConfigData into *apidef.
func (p *PluginConfigData) ExtractTo(api *apidef.APIDefinition) {
	api.ConfigDataDisabled = !p.Enabled
	api.ConfigData = p.Value
}

// PluginConfig holds configuration for custom plugins.
type PluginConfig struct {
	// Driver configures which custom plugin driver to use.
	// The value should be set to one of the following:
	//
	// - `otto`,
	// - `python`,
	// - `lua`,
	// - `grpc`,
	// - `goplugin`.
	//
	// Tyk classic API definition: `custom_middleware.driver`.
	Driver apidef.MiddlewareDriver `bson:"driver,omitempty" json:"driver,omitempty"`

	// Bundle configures custom plugin bundles.
	Bundle *PluginBundle `bson:"bundle,omitempty" json:"bundle,omitempty"`

	// Data configures custom plugin data.
	Data *PluginConfigData `bson:"data,omitempty" json:"data,omitempty"`
}

// Fill fills PluginConfig from apidef.
func (p *PluginConfig) Fill(api apidef.APIDefinition) {
	p.Driver = api.CustomMiddleware.Driver

	if p.Bundle == nil {
		p.Bundle = &PluginBundle{}
	}

	p.Bundle.Fill(api)
	if ShouldOmit(p.Bundle) {
		p.Bundle = nil
	}

	if p.Data == nil {
		p.Data = &PluginConfigData{}
	}

	p.Data.Fill(api)
	if ShouldOmit(p.Data) {
		p.Data = nil
	}
}

// ExtractTo extracts *PluginConfig into *apidef.
func (p *PluginConfig) ExtractTo(api *apidef.APIDefinition) {
	api.CustomMiddleware.Driver = p.Driver

	if p.Bundle == nil {
		p.Bundle = &PluginBundle{}
		defer func() {
			p.Bundle = nil
		}()
	}

	p.Bundle.ExtractTo(api)

	if p.Data == nil {
		p.Data = &PluginConfigData{}
		defer func() {
			p.Data = nil
		}()
	}

	p.Data.ExtractTo(api)
}

// PluginBundle holds configuration for custom plugins.
type PluginBundle struct {
	// Enabled activates the custom plugin bundles.
	//
	// Tyk classic API definition: `custom_middleware_bundle_disabled`
	Enabled bool `bson:"enabled" json:"enabled"` // required.
	// Path is the path suffix to construct the URL to fetch plugin bundle from.
	// Path will be suffixed to `bundle_base_url` in gateway config.
	Path string `bson:"path" json:"path"` // required.
}

// Fill fills PluginBundle from apidef.
func (p *PluginBundle) Fill(api apidef.APIDefinition) {
	p.Enabled = !api.CustomMiddlewareBundleDisabled
	p.Path = api.CustomMiddlewareBundle
}

// ExtractTo extracts *PluginBundle into *apidef.
func (p *PluginBundle) ExtractTo(api *apidef.APIDefinition) {
	api.CustomMiddlewareBundleDisabled = !p.Enabled
	api.CustomMiddlewareBundle = p.Path
}

// CORS holds configuration for cross-origin resource sharing.
type CORS struct {
	// Enabled is a boolean flag, if set to `true`, this option enables CORS processing.
	//
	// Tyk classic API definition: `CORS.enable`.
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// MaxAge indicates how long (in seconds) the results of a preflight request can be cached. The default is 0 which stands for no max age.
	//
	// Tyk classic API definition: `CORS.max_age`.
	MaxAge int `bson:"maxAge,omitempty" json:"maxAge,omitempty"`

	// AllowCredentials indicates if the request can include user credentials like cookies,
	// HTTP authentication or client side SSL certificates.
	//
	// Tyk classic API definition: `CORS.allow_credentials`.
	AllowCredentials bool `bson:"allowCredentials,omitempty" json:"allowCredentials,omitempty"`

	// ExposedHeaders indicates which headers are safe to expose to the API of a CORS API specification.
	//
	// Tyk classic API definition: `CORS.exposed_headers`.
	ExposedHeaders []string `bson:"exposedHeaders,omitempty" json:"exposedHeaders,omitempty"`

	// AllowedHeaders holds a list of non simple headers the client is allowed to use with cross-domain requests.
	//
	// Tyk classic API definition: `CORS.allowed_headers`.
	AllowedHeaders []string `bson:"allowedHeaders,omitempty" json:"allowedHeaders,omitempty"`

	// OptionsPassthrough is a boolean flag. If set to `true`, it will proxy the CORS OPTIONS pre-flight
	// request directly to upstream, without authentication and any CORS checks. This means that pre-flight
	// requests generated by web-clients such as SwaggerUI or the Tyk Portal documentation system
	// will be able to test the API using trial keys.
	//
	// If your service handles CORS natively, then enable this option.
	//
	// Tyk classic API definition: `CORS.options_passthrough`.
	OptionsPassthrough bool `bson:"optionsPassthrough,omitempty" json:"optionsPassthrough,omitempty"`

	// Debug is a boolean flag, If set to `true`, this option produces log files for the CORS middleware.
	//
	// Tyk classic API definition: `CORS.debug`.
	Debug bool `bson:"debug,omitempty" json:"debug,omitempty"`

	// AllowedOrigins holds a list of origin domains to allow access from. Wildcards are also supported, e.g. `http://*.foo.com`
	//
	// Tyk classic API definition: `CORS.allowed_origins`.
	AllowedOrigins []string `bson:"allowedOrigins,omitempty" json:"allowedOrigins,omitempty"`

	// AllowedMethods holds a list of methods to allow access via.
	//
	// Tyk classic API definition: `CORS.allowed_methods`.
	AllowedMethods []string `bson:"allowedMethods,omitempty" json:"allowedMethods,omitempty"`
}

// Fill fills *CORS from apidef.CORSConfig.
func (c *CORS) Fill(cors apidef.CORSConfig) {
	c.Enabled = cors.Enable
	c.MaxAge = cors.MaxAge
	c.AllowCredentials = cors.AllowCredentials
	c.ExposedHeaders = cors.ExposedHeaders
	c.AllowedHeaders = cors.AllowedHeaders
	c.OptionsPassthrough = cors.OptionsPassthrough
	c.Debug = cors.Debug
	c.AllowedOrigins = cors.AllowedOrigins
	c.AllowedMethods = cors.AllowedMethods
}

// ExtractTo extracts *CORS into *apidef.CORSConfig.
func (c *CORS) ExtractTo(cors *apidef.CORSConfig) {
	cors.Enable = c.Enabled
	cors.MaxAge = c.MaxAge
	cors.AllowCredentials = c.AllowCredentials
	cors.ExposedHeaders = c.ExposedHeaders
	cors.AllowedHeaders = c.AllowedHeaders
	cors.OptionsPassthrough = c.OptionsPassthrough
	cors.Debug = c.Debug
	cors.AllowedOrigins = c.AllowedOrigins
	cors.AllowedMethods = c.AllowedMethods
}

// Cache holds configuration for caching the requests.
type Cache struct {
	// Enabled turns global cache middleware on or off. It is still possible to enable caching on a per-path basis
	// by explicitly setting the endpoint cache middleware.
	//
	// Tyk classic API definition: `cache_options.enable_cache`
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// Timeout is the TTL for a cached object in seconds.
	//
	// Tyk classic API definition: `cache_options.cache_timeout`
	Timeout int64 `bson:"timeout,omitempty" json:"timeout,omitempty"`

	// CacheAllSafeRequests caches responses to (`GET`, `HEAD`, `OPTIONS`) requests overrides per-path cache settings in versions,
	// applies across versions.
	//
	// Tyk classic API definition: `cache_options.cache_all_safe_requests`
	CacheAllSafeRequests bool `bson:"cacheAllSafeRequests,omitempty" json:"cacheAllSafeRequests,omitempty"`

	// CacheResponseCodes is an array of response codes which are safe to cache e.g. `404`.
	//
	// Tyk classic API definition: `cache_options.cache_response_codes`
	CacheResponseCodes []int `bson:"cacheResponseCodes,omitempty" json:"cacheResponseCodes,omitempty"`

	// CacheByHeaders allows header values to be used as part of the cache key.
	//
	// Tyk classic API definition: `cache_options.cache_by_headers`
	CacheByHeaders []string `bson:"cacheByHeaders,omitempty" json:"cacheByHeaders,omitempty"`

	// EnableUpstreamCacheControl instructs Tyk Cache to respect upstream cache control headers.
	//
	// Tyk classic API definition: `cache_options.enable_upstream_cache_control`
	EnableUpstreamCacheControl bool `bson:"enableUpstreamCacheControl,omitempty" json:"enableUpstreamCacheControl,omitempty"`

	// ControlTTLHeaderName is the response header which tells Tyk how long it is safe to cache the response for.
	//
	// Tyk classic API definition: `cache_options.cache_control_ttl_header`
	ControlTTLHeaderName string `bson:"controlTTLHeaderName,omitempty" json:"controlTTLHeaderName,omitempty"`
}

// Fill fills *Cache from apidef.CacheOptions.
func (c *Cache) Fill(cache apidef.CacheOptions) {
	c.Enabled = cache.EnableCache
	c.Timeout = cache.CacheTimeout
	c.CacheAllSafeRequests = cache.CacheAllSafeRequests
	c.CacheResponseCodes = cache.CacheOnlyResponseCodes
	c.CacheByHeaders = cache.CacheByHeaders
	c.EnableUpstreamCacheControl = cache.EnableUpstreamCacheControl
	c.ControlTTLHeaderName = cache.CacheControlTTLHeader
}

// ExtractTo extracts *Cache into *apidef.CacheOptions.
func (c *Cache) ExtractTo(cache *apidef.CacheOptions) {
	cache.EnableCache = c.Enabled
	cache.CacheTimeout = c.Timeout
	cache.CacheAllSafeRequests = c.CacheAllSafeRequests
	cache.CacheOnlyResponseCodes = c.CacheResponseCodes
	cache.CacheByHeaders = c.CacheByHeaders
	cache.EnableUpstreamCacheControl = c.EnableUpstreamCacheControl
	cache.CacheControlTTLHeader = c.ControlTTLHeaderName
}

// Paths is a mapping of API endpoints to Path plugin configurations. This field is part of the [Middleware](#middleware) structure.
// The string keys in this object represent URL path patterns (e.g. `/users`, `/users/{id}`, `/api/*`) that match API endpoints.
type Paths map[string]*Path

// Fill fills *Paths (map) from apidef.ExtendedPathSet.
func (ps Paths) Fill(ep apidef.ExtendedPathsSet) {
	ps.fillAllowance(ep.WhiteList, allow)
	ps.fillAllowance(ep.BlackList, block)
	ps.fillAllowance(ep.Ignored, ignoreAuthentication)
	ps.fillTransformRequestMethod(ep.MethodTransforms)
	ps.fillCache(ep.AdvanceCacheConfig)
	ps.fillEnforceTimeout(ep.HardTimeouts)
}

func (ps Paths) fillAllowance(endpointMetas []apidef.EndPointMeta, typ AllowanceType) {
	for _, em := range endpointMetas {
		if _, ok := ps[em.Path]; !ok {
			ps[em.Path] = &Path{}
		}

		plugins := ps[em.Path].getMethod(em.Method)
		var allowance *Allowance

		switch typ {
		case block:
			if plugins.Block == nil {
				plugins.Block = &Allowance{}
			}

			allowance = plugins.Block
		case ignoreAuthentication:
			if plugins.IgnoreAuthentication == nil {
				plugins.IgnoreAuthentication = &Allowance{}
			}

			allowance = plugins.IgnoreAuthentication
		default:
			if plugins.Allow == nil {
				plugins.Allow = &Allowance{}
			}

			allowance = plugins.Allow
		}

		allowance.Fill(em)
		if ShouldOmit(allowance) {
			allowance = nil
		}
	}
}

func (ps Paths) fillTransformRequestMethod(metas []apidef.MethodTransformMeta) {
	for _, meta := range metas {
		if _, ok := ps[meta.Path]; !ok {
			ps[meta.Path] = &Path{}
		}

		plugins := ps[meta.Path].getMethod(meta.Method)
		if plugins.TransformRequestMethod == nil {
			plugins.TransformRequestMethod = &TransformRequestMethod{}
		}

		plugins.TransformRequestMethod.Fill(meta)
		if ShouldOmit(plugins.TransformRequestMethod) {
			plugins.TransformRequestMethod = nil
		}
	}
}

func (ps Paths) fillCache(cacheMetas []apidef.CacheMeta) {
	for _, cm := range cacheMetas {
		if _, ok := ps[cm.Path]; !ok {
			ps[cm.Path] = &Path{}
		}

		plugins := ps[cm.Path].getMethod(cm.Method)
		if plugins.Cache == nil {
			plugins.Cache = &CachePlugin{}
		}

		plugins.Cache.Fill(cm)
		if ShouldOmit(plugins.Cache) {
			plugins.Cache = nil
		}
	}
}

func (ps Paths) fillEnforceTimeout(metas []apidef.HardTimeoutMeta) {
	for _, meta := range metas {
		if _, ok := ps[meta.Path]; !ok {
			ps[meta.Path] = &Path{}
		}

		plugins := ps[meta.Path].getMethod(meta.Method)
		if plugins.EnforceTimeout == nil {
			plugins.EnforceTimeout = &EnforceTimeout{}
		}

		plugins.EnforceTimeout.Fill(meta)
		if ShouldOmit(plugins.EnforceTimeout) {
			plugins.EnforceTimeout = nil
		}
	}
}

// ExtractTo extracts Paths into *apidef.ExtendedPathsSet.
func (ps Paths) ExtractTo(ep *apidef.ExtendedPathsSet) {
	var paths []string
	for path := range ps {
		paths = append(paths, path)
	}

	sort.Strings(paths)

	for _, path := range paths {
		ps[path].ExtractTo(ep, path)
	}
}

// Path holds plugin configurations for HTTP method verbs.
type Path struct {
	// Delete holds plugin configuration for DELETE requests.
	Delete *Plugins `bson:"DELETE,omitempty" json:"DELETE,omitempty"`
	// Get holds plugin configuration for GET requests.
	Get *Plugins `bson:"GET,omitempty" json:"GET,omitempty"`
	// Head holds plugin configuration for HEAD requests.
	Head *Plugins `bson:"HEAD,omitempty" json:"HEAD,omitempty"`
	// Options holds plugin configuration for OPTIONS requests.
	Options *Plugins `bson:"OPTIONS,omitempty" json:"OPTIONS,omitempty"`
	// Patch holds plugin configuration for PATCH requests.
	Patch *Plugins `bson:"PATCH,omitempty" json:"PATCH,omitempty"`
	// Post holds plugin configuration for POST requests.
	Post *Plugins `bson:"POST,omitempty" json:"POST,omitempty"`
	// Put holds plugin configuration for PUT requests.
	Put *Plugins `bson:"PUT,omitempty" json:"PUT,omitempty"`
	// Trace holds plugin configuration for TRACE requests.
	Trace *Plugins `bson:"TRACE,omitempty" json:"TRACE,omitempty"`
	// Connect holds plugin configuration for CONNECT requests.
	Connect *Plugins `bson:"CONNECT,omitempty" json:"CONNECT,omitempty"`
}

// ExtractTo extracts *Path into *apidef.ExtendedPathSet.
func (p *Path) ExtractTo(ep *apidef.ExtendedPathsSet, path string) {
	if p.Get != nil {
		p.Get.ExtractTo(ep, path, http.MethodGet)
	}

	if p.Post != nil {
		p.Post.ExtractTo(ep, path, http.MethodPost)
	}

	if p.Put != nil {
		p.Put.ExtractTo(ep, path, http.MethodPut)
	}

	if p.Delete != nil {
		p.Delete.ExtractTo(ep, path, http.MethodDelete)
	}

	if p.Head != nil {
		p.Head.ExtractTo(ep, path, http.MethodHead)
	}

	if p.Options != nil {
		p.Options.ExtractTo(ep, path, http.MethodOptions)
	}

	if p.Trace != nil {
		p.Trace.ExtractTo(ep, path, http.MethodTrace)
	}

	if p.Patch != nil {
		p.Patch.ExtractTo(ep, path, http.MethodPatch)
	}

	if p.Connect != nil {
		p.Connect.ExtractTo(ep, path, http.MethodConnect)
	}
}

func (p *Path) getMethod(name string) *Plugins {
	switch {
	case strings.EqualFold(http.MethodGet, name):
		if p.Get == nil {
			p.Get = &Plugins{}
		}

		return p.Get
	case strings.EqualFold(http.MethodPost, name):
		if p.Post == nil {
			p.Post = &Plugins{}
		}

		return p.Post
	case strings.EqualFold(http.MethodPut, name):
		if p.Put == nil {
			p.Put = &Plugins{}
		}

		return p.Put
	case strings.EqualFold(http.MethodDelete, name):
		if p.Delete == nil {
			p.Delete = &Plugins{}
		}

		return p.Delete
	case strings.EqualFold(http.MethodHead, name):
		if p.Head == nil {
			p.Head = &Plugins{}
		}

		return p.Head
	case strings.EqualFold(http.MethodOptions, name):
		if p.Options == nil {
			p.Options = &Plugins{}
		}

		return p.Options
	case strings.EqualFold(http.MethodTrace, name):
		if p.Trace == nil {
			p.Trace = &Plugins{}
		}

		return p.Trace
	case strings.EqualFold(http.MethodPatch, name):
		if p.Patch == nil {
			p.Patch = &Plugins{}
		}

		return p.Patch
	case strings.EqualFold(http.MethodConnect, name):
		if p.Connect == nil {
			p.Connect = &Plugins{}
		}

		return p.Connect
	default:
		if p.Get == nil {
			p.Get = &Plugins{}
		}

		return p.Get
	}
}

// Plugins configures common settings for each plugin, allowances, transforms, caching and timeouts.
type Plugins struct {
	// Allow request by allowance.
	Allow *Allowance `bson:"allow,omitempty" json:"allow,omitempty"`

	// Block request by allowance.
	Block *Allowance `bson:"block,omitempty" json:"block,omitempty"`

	// IgnoreAuthentication ignores authentication on request by allowance.
	//
	// Tyk classic API definition: version_data.versions..extended_paths.ignored[].
	IgnoreAuthentication *Allowance `bson:"ignoreAuthentication,omitempty" json:"ignoreAuthentication,omitempty"`

	// TransformRequestMethod allows you to transform the method of a request.
	TransformRequestMethod *TransformRequestMethod `bson:"transformRequestMethod,omitempty" json:"transformRequestMethod,omitempty"`

	// Cache allows you to cache the server side response.
	Cache *CachePlugin `bson:"cache,omitempty" json:"cache,omitempty"`

	// EnforceTimeout allows you to configure a request timeout.
	EnforceTimeout *EnforceTimeout `bson:"enforcedTimeout,omitempty" json:"enforcedTimeout,omitempty"`
}

// ExtractTo extracts *Plugins into *apidef.ExtendedPathsSet.
func (p *Plugins) ExtractTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	p.extractAllowanceTo(ep, path, method, allow)
	p.extractAllowanceTo(ep, path, method, block)
	p.extractAllowanceTo(ep, path, method, ignoreAuthentication)
	p.extractTransformRequestMethodTo(ep, path, method)
	p.extractCacheTo(ep, path, method)
	p.extractEnforcedTimeoutTo(ep, path, method)
}

func (p *Plugins) extractAllowanceTo(ep *apidef.ExtendedPathsSet, path string, method string, typ AllowanceType) {
	allowance := p.Allow
	endpointMetas := &ep.WhiteList

	switch typ {
	case block:
		allowance = p.Block
		endpointMetas = &ep.BlackList
	case ignoreAuthentication:
		allowance = p.IgnoreAuthentication
		endpointMetas = &ep.Ignored
	}

	if allowance == nil {
		return
	}

	endpointMeta := apidef.EndPointMeta{Path: path, Method: method}
	allowance.ExtractTo(&endpointMeta)
	*endpointMetas = append(*endpointMetas, endpointMeta)
}

func (p *Plugins) extractTransformRequestMethodTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if p.TransformRequestMethod == nil {
		return
	}

	meta := apidef.MethodTransformMeta{Path: path, Method: method}
	p.TransformRequestMethod.ExtractTo(&meta)
	ep.MethodTransforms = append(ep.MethodTransforms, meta)
}

func (p *Plugins) extractCacheTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if p.Cache == nil {
		return
	}

	newCacheMeta := apidef.CacheMeta{
		Method: method,
		Path:   path,
	}
	p.Cache.ExtractTo(&newCacheMeta)
	ep.AdvanceCacheConfig = append(ep.AdvanceCacheConfig, newCacheMeta)
}

func (p *Plugins) extractEnforcedTimeoutTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if p.EnforceTimeout == nil {
		return
	}

	meta := apidef.HardTimeoutMeta{Path: path, Method: method}
	p.EnforceTimeout.ExtractTo(&meta)
	ep.HardTimeouts = append(ep.HardTimeouts, meta)
}

// Allowance describes allowance actions and behaviour.
type Allowance struct {
	// Enabled is a boolean flag, if set to `true`, then individual allowances (allow, block, ignore) will be enforced.
	Enabled bool `bson:"enabled" json:"enabled"`

	// IgnoreCase is a boolean flag, If set to `true`, checks for requests allowance will be case insensitive.
	IgnoreCase bool `bson:"ignoreCase,omitempty" json:"ignoreCase,omitempty"`
}

// Fill fills *Allowance from apidef.EndPointMeta.
func (a *Allowance) Fill(endpointMeta apidef.EndPointMeta) {
	a.Enabled = !endpointMeta.Disabled
	a.IgnoreCase = endpointMeta.IgnoreCase
}

// ExtractTo extracts the *Allowance into *apidef.EndPointMeta.
func (a *Allowance) ExtractTo(endpointMeta *apidef.EndPointMeta) {
	endpointMeta.Disabled = !a.Enabled
	endpointMeta.IgnoreCase = a.IgnoreCase
}

// Import enables an allowance based on the enabled argument.
func (a *Allowance) Import(enabled bool) {
	a.Enabled = enabled
}

// TransformRequestMethod holds configuration for rewriting request methods.
type TransformRequestMethod struct {
	// Enabled activates Method Transform for the given path and method.
	Enabled bool `bson:"enabled" json:"enabled"`
	// ToMethod is the http method value to which the method of an incoming request will be transformed.
	ToMethod string `bson:"toMethod" json:"toMethod"`
}

// Fill fills *TransformRequestMethod from apidef.MethodTransformMeta.
func (tm *TransformRequestMethod) Fill(meta apidef.MethodTransformMeta) {
	tm.Enabled = !meta.Disabled
	tm.ToMethod = meta.ToMethod
}

// ExtractTo extracts *TransformRequestMethod into *apidef.MethodTransformMeta.
func (tm *TransformRequestMethod) ExtractTo(meta *apidef.MethodTransformMeta) {
	meta.Disabled = !tm.Enabled
	meta.ToMethod = tm.ToMethod
}

// TransformBody holds configuration about request/response body transformations.
type TransformBody struct {
	// Enabled activates transform request/request body middleware.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.transform[].disabled` (negated).
	Enabled bool `bson:"enabled" json:"enabled"`
	// Format of the request/response body, xml or json.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.transform[].template_data.input_type`.
	Format apidef.RequestInputType `bson:"format" json:"format"`
	// Path file path for the template.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.transform[].template_data.template_source` when `template_data.template_mode` is `file`.
	Path string `bson:"path,omitempty" json:"path,omitempty"`
	// Body base64 encoded representation of the template.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.transform[].template_data.template_source` when `template_data.template_mode` is `blob`.
	Body string `bson:"body,omitempty" json:"body,omitempty"`
}

// Fill fills *TransformBody from apidef.TemplateMeta.
func (tr *TransformBody) Fill(meta apidef.TemplateMeta) {
	tr.Enabled = !meta.Disabled
	tr.Format = meta.TemplateData.Input
	if meta.TemplateData.Mode == apidef.UseBlob {
		tr.Body = meta.TemplateData.TemplateSource
	} else {
		tr.Path = meta.TemplateData.TemplateSource
	}
}

// ExtractTo extracts data from *TransformBody into *apidef.TemplateMeta.
func (tr *TransformBody) ExtractTo(meta *apidef.TemplateMeta) {
	meta.Disabled = !tr.Enabled
	meta.TemplateData.Input = tr.Format
	meta.TemplateData.EnableSession = true
	if tr.Body != "" {
		meta.TemplateData.Mode = apidef.UseBlob
		meta.TemplateData.TemplateSource = tr.Body
	} else {
		meta.TemplateData.Mode = apidef.UseFile
		meta.TemplateData.TemplateSource = tr.Path
	}
}

// TransformHeaders holds configuration about request/response header transformations.
type TransformHeaders struct {
	// Enabled activates Header Transform for the given path and method.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.transform_headers[].disabled` (negated).
	Enabled bool `bson:"enabled" json:"enabled"`
	// Remove specifies header names to be removed from the request/response.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.transform_headers[].delete_headers`.
	Remove []string `bson:"remove,omitempty" json:"remove,omitempty"`
	// Add specifies headers to be added to the request/response.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.transform_headers[].add_headers`.
	Add Headers `bson:"add,omitempty" json:"add,omitempty"`
}

// AppendAddOp appends add operation to TransformHeaders middleware.
func (th *TransformHeaders) AppendAddOp(name, value string) {
	th.Add = append(th.Add, Header{Name: name, Value: value})
}

// Fill fills *TransformHeaders from apidef.HeaderInjectionMeta.
func (th *TransformHeaders) Fill(meta apidef.HeaderInjectionMeta) {
	th.Enabled = !meta.Disabled
	th.Remove = meta.DeleteHeaders
	th.Add = NewHeaders(meta.AddHeaders)

	if len(th.Add) == 0 {
		th.Add = nil
	}
}

// ExtractTo extracts *TransformHeaders into *apidef.HeaderInjectionMeta.
func (th *TransformHeaders) ExtractTo(meta *apidef.HeaderInjectionMeta) {
	meta.Disabled = !th.Enabled
	meta.DeleteHeaders = th.Remove

	meta.AddHeaders = make(map[string]string, len(th.Remove))
	for _, header := range th.Add {
		meta.AddHeaders[header.Name] = header.Value
	}
}

// CachePlugin holds the configuration for the cache plugins.
type CachePlugin struct {
	// Enabled is a boolean flag. If set to `true`, the advanced caching plugin will be enabled.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.advance_cache_config[].disabled` (negated).
	Enabled bool `bson:"enabled" json:"enabled"`

	// CacheByRegex defines a regular expression used against the request body to produce a cache key.
	//
	// Example value: `\"id\":[^,]*` (quoted json value).
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.advance_cache_config[].cache_key_regex`.
	CacheByRegex string `bson:"cacheByRegex,omitempty" json:"cacheByRegex,omitempty"`

	// CacheResponseCodes contains a list of valid response codes for responses that are okay to add to the cache.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.advance_cache_config[].cache_response_codes`.
	CacheResponseCodes []int `bson:"cacheResponseCodes,omitempty" json:"cacheResponseCodes,omitempty"`

	// Timeout is the TTL for the endpoint level caching in seconds. 0 means no caching.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.advance_cache_config[].timeout`.
	Timeout int64 `bson:"timeout,omitempty" json:"timeout,omitempty"`
}

// Fill fills *CachePlugin from apidef.CacheMeta.
func (a *CachePlugin) Fill(cm apidef.CacheMeta) {
	a.Enabled = !cm.Disabled
	a.CacheByRegex = cm.CacheKeyRegex
	a.CacheResponseCodes = cm.CacheOnlyResponseCodes
	a.Timeout = cm.Timeout

	//TT-14102: Default cache timeout in seconds if none is specified but caching is enabled
	if a.Enabled && a.Timeout == 0 {
		a.Timeout = apidef.DefaultCacheTimeout
	}
}

// ExtractTo extracts *CachePlugin values to *apidef.CacheMeta.
func (a *CachePlugin) ExtractTo(cm *apidef.CacheMeta) {
	cm.Disabled = !a.Enabled
	cm.CacheKeyRegex = a.CacheByRegex
	cm.CacheOnlyResponseCodes = a.CacheResponseCodes
	cm.Timeout = a.Timeout
}

// EnforceTimeout holds the configuration for enforcing request timeouts.
type EnforceTimeout struct {
	// Enabled is a boolean flag. If set to `true`, requests will enforce a configured timeout.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.hard_timeouts[].disabled` (negated).
	Enabled bool `bson:"enabled" json:"enabled"`

	// Value is the configured timeout in seconds.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.hard_timeouts[].timeout`.
	Value int `bson:"value" json:"value"`
}

// Fill fills *EnforceTimeout from apidef.HardTimeoutMeta.
func (et *EnforceTimeout) Fill(meta apidef.HardTimeoutMeta) {
	et.Enabled = !meta.Disabled
	et.Value = meta.TimeOut
}

// ExtractTo extracts *EnforceTimeout to *apidef.HardTimeoutMeta.
func (et *EnforceTimeout) ExtractTo(meta *apidef.HardTimeoutMeta) {
	meta.Disabled = !et.Enabled
	meta.TimeOut = et.Value
}

// CustomPlugin configures custom plugin.
type CustomPlugin struct {
	// Enabled activates the custom plugin.
	//
	// Tyk classic API definition: `custom_middleware.pre[].disabled`, `custom_middleware.post_key_auth[].disabled`,
	// `custom_middleware.post[].disabled`, `custom_middleware.response[].disabled` (negated).
	Enabled bool `bson:"enabled" json:"enabled"` // required.
	// FunctionName is the name of authentication method.
	//
	// Tyk classic API definition: `custom_middleware.pre[].name`, `custom_middleware.post_key_auth[].name`,
	// `custom_middleware.post[].name`, `custom_middleware.response[].name`.
	FunctionName string `bson:"functionName" json:"functionName"` // required.
	// Path is the path to shared object file in case of goplugin mode or path to JS code in case of otto auth plugin.
	//
	// Tyk classic API definition: `custom_middleware.pre[].path`, `custom_middleware.post_key_auth[].path`,
	// `custom_middleware.post[].path`, `custom_middleware.response[].path`.
	Path string `bson:"path" json:"path"`
	// RawBodyOnly if set to true, do not fill body in request or response object.
	//
	// Tyk classic API definition: `custom_middleware.pre[].raw_body_only`, `custom_middleware.post_key_auth[].raw_body_only`,
	// `custom_middleware.post[].raw_body_only`, `custom_middleware.response[].raw_body_only`.
	RawBodyOnly bool `bson:"rawBodyOnly,omitempty" json:"rawBodyOnly,omitempty"`
	// RequireSession if set to true passes down the session information for plugins after authentication.
	// RequireSession is used only with JSVM custom middleware.
	//
	// Tyk classic API definition: `custom_middleware.pre[].require_session`, `custom_middleware.post_key_auth[].require_session`,
	// `custom_middleware.post[].require_session`, `custom_middleware.response[].require_session`.
	RequireSession bool `bson:"requireSession,omitempty" json:"requireSession,omitempty"`
}

// CustomPlugins is a list of CustomPlugin objects.
type CustomPlugins []CustomPlugin

// Fill fills CustomPlugins from supplied Middleware definitions.
func (c *CustomPlugins) Fill(mwDefs []apidef.MiddlewareDefinition) {
	if len(mwDefs) == 0 {
		return
	}

	customPlugins := make(CustomPlugins, len(mwDefs))
	for i, mwDef := range mwDefs {
		customPlugins[i] = CustomPlugin{
			Enabled:        !mwDef.Disabled,
			Path:           mwDef.Path,
			FunctionName:   mwDef.Name,
			RawBodyOnly:    mwDef.RawBodyOnly,
			RequireSession: mwDef.RequireSession,
		}
	}

	*c = customPlugins
}

// ExtractTo extracts CustomPlugins into supplied Middleware definitions.
func (c *CustomPlugins) ExtractTo(mwDefs []apidef.MiddlewareDefinition) {
	if c == nil {
		return
	}

	for i, plugin := range *c {
		mwDefs[i] = apidef.MiddlewareDefinition{
			Disabled:       !plugin.Enabled,
			Name:           plugin.FunctionName,
			Path:           plugin.Path,
			RawBodyOnly:    plugin.RawBodyOnly,
			RequireSession: plugin.RequireSession,
		}
	}
}

// PrePlugin configures pre-request plugins.
//
// Pre-request plugins are executed before the request is sent to the
// upstream target and before any authentication information is extracted
// from the header or parameter list of the request.
type PrePlugin struct {
	// Plugins configures custom plugins to be run on pre authentication stage.
	// The plugins would be executed in the order of configuration in the list.
	Plugins CustomPlugins `bson:"plugins,omitempty" json:"plugins,omitempty"`
}

// Fill fills PrePlugin from supplied Tyk classic api definition.
func (p *PrePlugin) Fill(api apidef.APIDefinition) {
	if len(api.CustomMiddleware.Pre) == 0 {
		p.Plugins = nil
		return
	}

	p.Plugins = make(CustomPlugins, len(api.CustomMiddleware.Pre))
	p.Plugins.Fill(api.CustomMiddleware.Pre)
}

// ExtractTo extracts PrePlugin into Tyk classic api definition.
func (p *PrePlugin) ExtractTo(api *apidef.APIDefinition) {
	if len(p.Plugins) == 0 {
		api.CustomMiddleware.Pre = nil
		return
	}

	api.CustomMiddleware.Pre = make([]apidef.MiddlewareDefinition, len(p.Plugins))
	p.Plugins.ExtractTo(api.CustomMiddleware.Pre)
}

// PostAuthenticationPlugin configures post authentication plugins.
type PostAuthenticationPlugin struct {
	// Plugins configures custom plugins to be run on pre authentication stage.
	// The plugins would be executed in the order of configuration in the list.
	Plugins CustomPlugins `bson:"plugins,omitempty" json:"plugins,omitempty"`
}

// Fill fills PostAuthenticationPlugin from supplied Tyk classic api definition.
func (p *PostAuthenticationPlugin) Fill(api apidef.APIDefinition) {
	if len(api.CustomMiddleware.PostKeyAuth) == 0 {
		p.Plugins = nil
		return
	}

	p.Plugins = make(CustomPlugins, len(api.CustomMiddleware.PostKeyAuth))
	p.Plugins.Fill(api.CustomMiddleware.PostKeyAuth)
}

// ExtractTo extracts PostAuthenticationPlugin into Tyk classic api definition.
func (p *PostAuthenticationPlugin) ExtractTo(api *apidef.APIDefinition) {
	if len(p.Plugins) == 0 {
		api.CustomMiddleware.PostKeyAuth = nil
		return
	}

	api.CustomMiddleware.PostKeyAuth = make([]apidef.MiddlewareDefinition, len(p.Plugins))
	p.Plugins.ExtractTo(api.CustomMiddleware.PostKeyAuth)
}

// PostPlugin configures post plugins.
type PostPlugin struct {
	// Plugins configures custom plugins to be run on post stage.
	// The plugins would be executed in the order of configuration in the list.
	Plugins CustomPlugins `bson:"plugins,omitempty" json:"plugins,omitempty"`
}

// Fill fills PostPlugin from supplied Tyk classic api definition.
func (p *PostPlugin) Fill(api apidef.APIDefinition) {
	if len(api.CustomMiddleware.Post) == 0 {
		p.Plugins = nil
		return
	}

	p.Plugins = make(CustomPlugins, len(api.CustomMiddleware.Post))
	p.Plugins.Fill(api.CustomMiddleware.Post)
}

// ExtractTo extracts PostPlugin into Tyk classic api definition.
func (p *PostPlugin) ExtractTo(api *apidef.APIDefinition) {
	if len(p.Plugins) == 0 {
		api.CustomMiddleware.Post = nil
		return
	}

	api.CustomMiddleware.Post = make([]apidef.MiddlewareDefinition, len(p.Plugins))
	p.Plugins.ExtractTo(api.CustomMiddleware.Post)
}

// ResponsePlugin configures response plugins.
type ResponsePlugin struct {
	// Plugins configures custom plugins to be run on post stage.
	// The plugins would be executed in the order of configuration in the list.
	Plugins CustomPlugins `bson:"plugins,omitempty" json:"plugins,omitempty"`
}

// Fill fills ResponsePlugin from supplied Tyk classic api definition.
func (p *ResponsePlugin) Fill(api apidef.APIDefinition) {
	if len(api.CustomMiddleware.Response) == 0 {
		p.Plugins = nil
		return
	}

	p.Plugins = make(CustomPlugins, len(api.CustomMiddleware.Response))
	p.Plugins.Fill(api.CustomMiddleware.Response)
}

// ExtractTo extracts PostPlugin into Tyk classic api definition.
func (p *ResponsePlugin) ExtractTo(api *apidef.APIDefinition) {
	if len(p.Plugins) == 0 {
		api.CustomMiddleware.Response = nil
		return
	}

	api.CustomMiddleware.Response = make([]apidef.MiddlewareDefinition, len(p.Plugins))
	p.Plugins.ExtractTo(api.CustomMiddleware.Response)
}

// VirtualEndpoint contains virtual endpoint configuration.
type VirtualEndpoint struct {
	// Enabled activates virtual endpoint.
	//
	// Tyk classic API definition: `virtual.disabled` (negated).
	Enabled bool `bson:"enabled" json:"enabled"` // required.
	// Name is the name of plugin function to be executed.
	// Deprecated: Use FunctionName instead.
	Name string `bson:"name,omitempty" json:"name,omitempty"`
	// FunctionName is the name of plugin function to be executed.
	//
	// Tyk classic API definition: `virtual.response_function_name`.
	FunctionName string `bson:"functionName" json:"functionName"` // required.
	// Path is the path to JS file.
	//
	// Tyk classic API definition: `virtual.function_source_uri` when `virtual.function_source_type` is `file`.
	Path string `bson:"path,omitempty" json:"path,omitempty"`
	// Body is the JS function to execute encoded in base64 format.
	//
	// Tyk classic API definition: `virtual.function_source_uri` when `virtual.function_source_type` is `blob`.
	Body string `bson:"body,omitempty" json:"body,omitempty"`
	// ProxyOnError proxies if virtual endpoint errors out.
	//
	// Tyk classic API definition: `virtual.proxy_on_error`.
	ProxyOnError bool `bson:"proxyOnError,omitempty" json:"proxyOnError,omitempty"`
	// RequireSession if enabled passes session to virtual endpoint.
	//
	// Tyk classic API definition: `virtual.use_session`.
	RequireSession bool `bson:"requireSession,omitempty" json:"requireSession,omitempty"`
}

// MarshalJSON is a custom JSON marshaler for the VirtualEndpoint struct. It is implemented
// to facilitate a smooth migration from deprecated fields that were previously used to represent
// the same data.
func (v *VirtualEndpoint) MarshalJSON() ([]byte, error) {
	if v == nil {
		return nil, nil
	}

	type Alias VirtualEndpoint

	var payload = Alias(*v)

	if payload.FunctionName == "" && payload.Name != "" {
		payload.FunctionName = payload.Name
		payload.Name = ""
	}

	// to prevent infinite recursion
	return json.Marshal(payload)
}

// Fill fills *VirtualEndpoint from apidef.VirtualMeta.
func (v *VirtualEndpoint) Fill(meta apidef.VirtualMeta) {
	v.Enabled = !meta.Disabled
	v.FunctionName = meta.ResponseFunctionName
	v.Name = ""
	v.RequireSession = meta.UseSession
	v.ProxyOnError = meta.ProxyOnError
	if meta.FunctionSourceType == apidef.UseBlob {
		v.Body = meta.FunctionSourceURI
	} else {
		v.Path = meta.FunctionSourceURI
	}
}

// ExtractTo extracts *VirtualEndpoint to *apidef.VirtualMeta.
func (v *VirtualEndpoint) ExtractTo(meta *apidef.VirtualMeta) {
	meta.Disabled = !v.Enabled
	if v.FunctionName != "" {
		meta.ResponseFunctionName = v.FunctionName
		v.Name = ""
	} else {
		meta.ResponseFunctionName = v.Name
	}

	meta.UseSession = v.RequireSession
	meta.ProxyOnError = v.ProxyOnError
	if v.Body != "" {
		meta.FunctionSourceType = apidef.UseBlob
		meta.FunctionSourceURI = v.Body
	} else {
		meta.FunctionSourceType = apidef.UseFile
		meta.FunctionSourceURI = v.Path
	}
}

// EndpointPostPlugins is a list of EndpointPostPlugins. It's used where multiple plugins can be run.
type EndpointPostPlugins []EndpointPostPlugin

// EndpointPostPlugin contains endpoint level post plugin configuration.
type EndpointPostPlugin struct {
	// Enabled activates post plugin.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.go_plugin.disabled`(negated).
	Enabled bool `bson:"enabled" json:"enabled"` // required.
	// Name is the name of plugin function to be executed.
	// Deprecated: Use FunctionName instead.
	Name string `bson:"name,omitempty" json:"name,omitempty"`
	// FunctionName is the name of plugin function to be executed.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.go_plugin.symbol_name`(negated).
	FunctionName string `bson:"functionName" json:"functionName"` // required.
	// Path is the path to plugin.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.go_plugin.plugin_path`(negated).
	Path string `bson:"path" json:"path"` // required.
}

// MarshalJSON is a custom JSON marshaler for the EndpointPostPlugin struct. It is implemented
// to facilitate a smooth migration from deprecated fields that were previously used to represent
// the same data.
func (ep *EndpointPostPlugin) MarshalJSON() ([]byte, error) {
	if ep == nil {
		return nil, nil
	}

	// to prevent infinite recursion
	type Alias EndpointPostPlugin

	payload := Alias(*ep)
	if payload.FunctionName == "" && payload.Name != "" {
		payload.FunctionName = payload.Name
		payload.Name = ""
	}

	return json.Marshal(payload)
}

// Fill fills *EndpointPostPlugin from apidef.GoPluginMeta.
func (e EndpointPostPlugins) Fill(meta apidef.GoPluginMeta) {
	if len(e) == 0 {
		return
	}

	e[0] = EndpointPostPlugin{
		Enabled:      !meta.Disabled,
		FunctionName: meta.SymbolName,
		Path:         meta.PluginPath,
	}
}

// ExtractTo extracts *EndpointPostPlugin to *apidef.GoPluginMeta.
func (e EndpointPostPlugins) ExtractTo(meta *apidef.GoPluginMeta) {
	if len(e) == 0 {
		return
	}

	meta.Disabled = !e[0].Enabled
	meta.PluginPath = e[0].Path
	if e[0].FunctionName != "" {
		meta.SymbolName = e[0].FunctionName
	} else {
		meta.SymbolName = e[0].Name
	}
}

// CircuitBreaker holds configuration for the circuit breaker middleware.
// Tyk classic API definition: `version_data.versions..extended_paths.circuit_breakers[*]`.
type CircuitBreaker struct {
	// Enabled activates the Circuit Breaker functionality.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.circuit_breakers[*].disabled` (negated).
	Enabled bool `bson:"enabled" json:"enabled"`
	// Threshold is the proportion from each `sampleSize` requests that must fail for the breaker to be tripped. This must be a value between 0.0 and 1.0. If `sampleSize` is 100 then a threshold of 0.4 means that the breaker will be tripped if 40 out of every 100 requests fails.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.circuit_breakers[*].threshold_percent`.
	Threshold float64 `bson:"threshold" json:"threshold"`
	// SampleSize is the size of the circuit breaker sampling window. Combining this with `threshold` gives the failure rate required to trip the circuit breaker.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.circuit_breakers[*].samples`.
	SampleSize int `bson:"sampleSize" json:"sampleSize"`
	// CoolDownPeriod is the period of time (in seconds) for which the circuit breaker will remain open before returning to service.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.circuit_breakers[*].return_to_service_after`.
	CoolDownPeriod int `bson:"coolDownPeriod" json:"coolDownPeriod"`
	// HalfOpenStateEnabled , if enabled, allows some requests to pass through the circuit breaker during the cool down period. If Tyk detects that the path is now working, the circuit breaker will be automatically reset and traffic will be resumed to the upstream.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.circuit_breakers[*].disable_half_open_state` (negated).
	HalfOpenStateEnabled bool `bson:"halfOpenStateEnabled" json:"halfOpenStateEnabled"`
}

// Fill fills *CircuitBreaker from apidef.CircuitBreakerMeta.
func (cb *CircuitBreaker) Fill(circuitBreaker apidef.CircuitBreakerMeta) {
	cb.Enabled = !circuitBreaker.Disabled
	cb.Threshold = circuitBreaker.ThresholdPercent
	cb.SampleSize = int(circuitBreaker.Samples)
	cb.CoolDownPeriod = circuitBreaker.ReturnToServiceAfter
	cb.HalfOpenStateEnabled = !circuitBreaker.DisableHalfOpenState
}

// ExtractTo extracts *CircuitBreaker into *apidef.CircuitBreakerMeta.
func (cb *CircuitBreaker) ExtractTo(circuitBreaker *apidef.CircuitBreakerMeta) {
	circuitBreaker.Disabled = !cb.Enabled
	circuitBreaker.ThresholdPercent = cb.Threshold
	circuitBreaker.Samples = int64(cb.SampleSize)
	circuitBreaker.ReturnToServiceAfter = cb.CoolDownPeriod
	circuitBreaker.DisableHalfOpenState = !cb.HalfOpenStateEnabled
}

// RequestSizeLimit limits the maximum allowed size of the request body in bytes.
type RequestSizeLimit struct {
	// Enabled activates the Request Size Limit functionality.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.size_limits[].disabled` (negated).
	Enabled bool `bson:"enabled" json:"enabled"`
	// Value is the maximum allowed size of the request body in bytes.
	//
	// Tyk classic API definition: `version_data.versions..extended_paths.size_limits[].size_limit`.
	Value int64 `bson:"value" json:"value"`
}

// Fill fills *RequestSizeLimit from apidef.RequestSizeMeta.
func (r *RequestSizeLimit) Fill(meta apidef.RequestSizeMeta) {
	r.Enabled = !meta.Disabled
	r.Value = meta.SizeLimit
}

// ExtractTo extracts *RequestSizeLimiter into *apidef.RequestSizeMeta.
func (r *RequestSizeLimit) ExtractTo(meta *apidef.RequestSizeMeta) {
	meta.Disabled = !r.Enabled
	meta.SizeLimit = r.Value
}

// TrafficLogs holds configuration about API log analytics.
type TrafficLogs struct {
	// Enabled enables traffic log analytics for the API.
	// Tyk classic API definition: `do_not_track`.
	Enabled bool `bson:"enabled" json:"enabled"`
	// TagHeaders is a string array of HTTP headers that can be extracted
	// and transformed into analytics tags (statistics aggregated by tag, per hour).
	TagHeaders []string `bson:"tagHeaders" json:"tagHeaders,omitempty"`
	// CustomRetentionPeriod configures a custom value for how long the analytics is retained for,
	// defaults to 100 years.
	CustomRetentionPeriod ReadableDuration `bson:"customRetentionPeriod,omitempty" json:"customRetentionPeriod,omitempty"`
	// Plugins configures custom plugins to allow for extensive modifications to analytics records
	// The plugins would be executed in the order of configuration in the list.
	Plugins CustomAnalyticsPlugins `bson:"plugins,omitempty" json:"plugins,omitempty"`
}

// Fill fills *TrafficLogs from apidef.APIDefinition.
func (t *TrafficLogs) Fill(api apidef.APIDefinition) {
	t.Enabled = !api.DoNotTrack
	t.TagHeaders = api.TagHeaders
	t.CustomRetentionPeriod = ReadableDuration(time.Duration(api.ExpireAnalyticsAfter) * time.Second)

	if t.Plugins == nil {
		t.Plugins = make(CustomAnalyticsPlugins, 0)
	}
	t.Plugins.Fill(api)
	if ShouldOmit(t.Plugins) {
		t.Plugins = nil
	}
}

// ExtractTo extracts *TrafficLogs into *apidef.APIDefinition.
func (t *TrafficLogs) ExtractTo(api *apidef.APIDefinition) {
	api.DoNotTrack = !t.Enabled
	api.TagHeaders = t.TagHeaders
	api.ExpireAnalyticsAfter = int64(t.CustomRetentionPeriod.Seconds())

	if t.Plugins == nil {
		t.Plugins = make(CustomAnalyticsPlugins, 0)
		defer func() {
			t.Plugins = nil
		}()
	}
	t.Plugins.ExtractTo(api)
}

// CustomAnalyticsPlugins is a list of CustomPlugin objects for analytics.
type CustomAnalyticsPlugins []CustomPlugin

// Fill fills CustomAnalyticsPlugins from AnalyticsPlugin in the supplied api.
func (c *CustomAnalyticsPlugins) Fill(api apidef.APIDefinition) {
	if api.AnalyticsPlugin.Enabled {
		customPlugins := []CustomPlugin{
			{
				Enabled:      api.AnalyticsPlugin.Enabled,
				FunctionName: api.AnalyticsPlugin.FuncName,
				Path:         api.AnalyticsPlugin.PluginPath,
			},
		}
		*c = customPlugins
	}
}

// ExtractTo extracts CustomAnalyticsPlugins into AnalyticsPlugin of supplied api.
func (c *CustomAnalyticsPlugins) ExtractTo(api *apidef.APIDefinition) {
	if len(*c) > 0 {
		// extract the first item in the customAnalyticsPlugin into apidef
		plugin := (*c)[0]
		api.AnalyticsPlugin.Enabled = plugin.Enabled
		api.AnalyticsPlugin.FuncName = plugin.FunctionName
		api.AnalyticsPlugin.PluginPath = plugin.Path
	}
}

// GlobalRequestSizeLimit holds configuration about the global limits for request sizes.
type GlobalRequestSizeLimit struct {
	// Enabled activates the Request Size Limit.
	//
	// Tyk classic API definition: `version_data.versions..global_size_limit_disabled` (negated).
	Enabled bool `bson:"enabled" json:"enabled"`
	// Value contains the value of the request size limit.
	//
	// Tyk classic API definition: `version_data.versions..global_size_limit`.
	Value int64 `bson:"value" json:"value"`
}

// Fill fills *GlobalRequestSizeLimit from apidef.APIDefinition.
func (g *GlobalRequestSizeLimit) Fill(api apidef.APIDefinition) {
	ok := false
	if api.VersionData.Versions != nil {
		_, ok = api.VersionData.Versions[Main]
	}
	if !ok || api.VersionData.Versions[Main].GlobalSizeLimit == 0 {
		g.Enabled = false
		g.Value = 0
		return
	}

	g.Enabled = !api.VersionData.Versions[Main].GlobalSizeLimitDisabled
	g.Value = api.VersionData.Versions[Main].GlobalSizeLimit
}

// ExtractTo extracts *GlobalRequestSizeLimit into *apidef.APIDefinition.
func (g *GlobalRequestSizeLimit) ExtractTo(api *apidef.APIDefinition) {
	mainVersion := requireMainVersion(api)
	defer func() {
		updateMainVersion(api, mainVersion)
	}()

	if g.Value == 0 {
		mainVersion.GlobalSizeLimit = 0
		mainVersion.GlobalSizeLimitDisabled = true
		return
	}

	mainVersion.GlobalSizeLimitDisabled = !g.Enabled
	mainVersion.GlobalSizeLimit = g.Value
}

// ContextVariables holds the configuration related to Tyk context variables.
type ContextVariables struct {
	// Enabled provides access to context variables from specific Tyk middleware (URL rewrite, header and body transform).
	//
	// Tyk classic API definition: `enable_context_vars`.
	Enabled bool `json:"enabled" bson:"enabled"`
}

// Fill fills *ContextVariables from apidef.APIDefinition.
func (c *ContextVariables) Fill(api apidef.APIDefinition) {
	c.Enabled = api.EnableContextVars
}

// ExtractTo extracts *ContextVariables into *apidef.APIDefinition.
func (c *ContextVariables) ExtractTo(api *apidef.APIDefinition) {
	api.EnableContextVars = c.Enabled
}

// IgnoreCase will make route matching be case insensitive.
// This accepts request to `/AAA` or `/aaa` if set to true.
type IgnoreCase struct {
	// Enabled activates case insensitive route matching.
	//
	// Tyk classic API definition: `version_data.versions..ignore_endpoint_case`.
	Enabled bool `json:"enabled" bson:"enabled"`
}

// Fill fills *IgnoreCase from apidef.APIDefinition.
func (p *IgnoreCase) Fill(api apidef.APIDefinition) {
	ok := false
	if api.VersionData.Versions != nil {
		_, ok = api.VersionData.Versions[Main]
	}
	if !ok {
		p.Enabled = false
		return
	}

	p.Enabled = api.VersionData.Versions[Main].IgnoreEndpointCase
}

func (g *Global) fillIgnoreCase(api apidef.APIDefinition) {
	if g.IgnoreCase == nil {
		g.IgnoreCase = &IgnoreCase{}
	}

	g.IgnoreCase.Fill(api)

	if !g.IgnoreCase.Enabled {
		g.IgnoreCase = nil
	}
}

func (g *Global) extractIgnoreCase(api *apidef.APIDefinition) {
	if g.IgnoreCase == nil {
		g.IgnoreCase = &IgnoreCase{}
		defer func() {
			g.IgnoreCase = nil
		}()
	}

	g.IgnoreCase.ExtractTo(api)
}

// ExtractTo extracts *IgnoreCase into *apidef.APIDefinition.
func (p *IgnoreCase) ExtractTo(api *apidef.APIDefinition) {
	mainVersion := requireMainVersion(api)
	defer func() {
		updateMainVersion(api, mainVersion)
	}()

	mainVersion.IgnoreEndpointCase = p.Enabled
}
