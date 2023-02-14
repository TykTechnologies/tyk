package oas

import (
	"net/http"
	"sort"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
)

// Middleware holds configuration for middleware.
type Middleware struct {
	// Global contains the configurations related to the global middleware.
	Global *Global `bson:"global,omitempty" json:"global,omitempty"`

	// Operations configuration.
	Operations Operations `bson:"operations,omitempty" json:"operations,omitempty"`
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
	if m.Global != nil {
		m.Global.ExtractTo(api)
	}
}

// Global holds configuration applies globally: CORS and caching.
type Global struct {
	// PluginConfig contains the configuration related custom plugin bundles/driver.
	PluginConfig *PluginConfig `bson:"pluginConfig,omitempty" json:"pluginConfig,omitempty"`

	// CORS contains the configuration related to cross origin resource sharing.
	// Tyk classic API definition: `CORS`.
	CORS *CORS `bson:"cors,omitempty" json:"cors,omitempty"`

	// PrePlugin contains configuration related to custom pre-authentication plugin.
	// Tyk classic API definition: `custom_middleware.pre`.
	PrePlugin *PrePlugin `bson:"prePlugin,omitempty" json:"prePlugin,omitempty"`

	// PostAuthenticationPlugin contains configuration related to custom post authentication plugin.
	// Tyk classic API definition: `custom_middleware.post_key_auth`.
	PostAuthenticationPlugin *PostAuthenticationPlugin `bson:"postAuthenticationPlugin,omitempty" json:"postAuthenticationPlugin,omitempty"`

	// PostPlugin contains configuration related to custom post plugin.
	// Tyk classic API definition: `custom_middleware.post`.
	PostPlugin *PostPlugin `bson:"postPlugin,omitempty" json:"postPlugin,omitempty"`

	// ResponsePlugin contains configuration related to custom post plugin.
	// Tyk classic API definition: `custom_middleware.response`.
	ResponsePlugin *ResponsePlugin `bson:"responsePlugin,omitempty" json:"responsePlugin,omitempty"`

	// Cache contains the configurations related to caching.
	// Tyk classic API definition: `cache_options`.
	Cache *Cache `bson:"cache,omitempty" json:"cache,omitempty"`
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

	if g.PrePlugin == nil {
		g.PrePlugin = &PrePlugin{}
	}

	g.PrePlugin.Fill(api)
	if ShouldOmit(g.PrePlugin) {
		g.PrePlugin = nil
	}

	if g.PostAuthenticationPlugin == nil {
		g.PostAuthenticationPlugin = &PostAuthenticationPlugin{}
	}

	g.PostAuthenticationPlugin.Fill(api)
	if ShouldOmit(g.PostAuthenticationPlugin) {
		g.PostAuthenticationPlugin = nil
	}

	if g.PostPlugin == nil {
		g.PostPlugin = &PostPlugin{}
	}

	g.PostPlugin.Fill(api)
	if ShouldOmit(g.PostPlugin) {
		g.PostPlugin = nil
	}

	if g.Cache == nil {
		g.Cache = &Cache{}
	}

	g.Cache.Fill(api.CacheOptions)
	if ShouldOmit(g.Cache) {
		g.Cache = nil
	}

	if g.ResponsePlugin == nil {
		g.ResponsePlugin = &ResponsePlugin{}
	}

	g.ResponsePlugin.Fill(api)
	if ShouldOmit(g.ResponsePlugin) {
		g.ResponsePlugin = nil
	}
}

// ExtractTo extracts *Global into *apidef.APIDefinition.
func (g *Global) ExtractTo(api *apidef.APIDefinition) {
	if g.PluginConfig != nil {
		g.PluginConfig.ExtractTo(api)
	}

	if g.CORS != nil {
		g.CORS.ExtractTo(&api.CORS)
	}

	if g.PrePlugin != nil {
		g.PrePlugin.ExtractTo(api)
	}

	if g.PostAuthenticationPlugin != nil {
		g.PostAuthenticationPlugin.ExtractTo(api)
	}

	if g.PostPlugin != nil {
		g.PostPlugin.ExtractTo(api)
	}

	if g.Cache != nil {
		g.Cache.ExtractTo(&api.CacheOptions)
	}

	if g.ResponsePlugin != nil {
		g.ResponsePlugin.ExtractTo(api)
	}
}

// PluginConfigData configures config data for custom plugins.
type PluginConfigData struct {
	// Enabled enables custom plugin config data.
	Enabled bool `bson:"enabled" json:"enabled"`

	// Value is the value of custom plugin config data.
	Value map[string]interface{} `bson:"value" json:"value"`
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
	// Driver configures which custom plugin to be used.
	// It's value should be set to one of the following:
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

	if p.Bundle != nil {
		p.Bundle.ExtractTo(api)
	}

	if p.Data != nil {
		p.Data.ExtractTo(api)
	}
}

// PluginBundle holds configuration for custom plugins.
type PluginBundle struct {
	// Enabled enables the custom plugin bundles.
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

	// AllowCredentials indicates whether the request can include user credentials like cookies,
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

// Paths is a mapping of API endpoints to Path plugin configurations.
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
	Delete  *Plugins `bson:"DELETE,omitempty" json:"DELETE,omitempty"`
	Get     *Plugins `bson:"GET,omitempty" json:"GET,omitempty"`
	Head    *Plugins `bson:"HEAD,omitempty" json:"HEAD,omitempty"`
	Options *Plugins `bson:"OPTIONS,omitempty" json:"OPTIONS,omitempty"`
	Patch   *Plugins `bson:"PATCH,omitempty" json:"PATCH,omitempty"`
	Post    *Plugins `bson:"POST,omitempty" json:"POST,omitempty"`
	Put     *Plugins `bson:"PUT,omitempty" json:"PUT,omitempty"`
	Trace   *Plugins `bson:"TRACE,omitempty" json:"TRACE,omitempty"`
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

	// Ignore authentication on request by allowance.
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

// Header holds a header name and value pair.
type Header struct {
	// Name is the name of the header.
	Name string `bson:"name" json:"name"`
	// Value is the value of the header.
	Value string `bson:"value" json:"value"`
}

// TransformRequestMethod holds configuration for rewriting request methods.
type TransformRequestMethod struct {
	// Enabled enables Method Transform for the given path and method.
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

// TransformRequestBody holds configuration about body request transformations.
type TransformRequestBody struct {
	// Enabled enables transform request body middleware.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Format of the request body, xml or json.
	Format apidef.RequestInputType `bson:"format" json:"format"`
	// Path file path for the template.
	Path string `bson:"path,omitempty" json:"path,omitempty"`
	// Body base64 encoded representation of the template.
	Body string `bson:"body,omitempty" json:"body,omitempty"`
}

// Fill fills *TransformRequestBody from apidef.TemplateMeta.
func (tr *TransformRequestBody) Fill(meta apidef.TemplateMeta) {
	tr.Enabled = !meta.Disabled
	tr.Format = meta.TemplateData.Input
	if meta.TemplateData.Mode == apidef.UseBlob {
		tr.Body = meta.TemplateData.TemplateSource
	} else {
		tr.Path = meta.TemplateData.TemplateSource
	}
}

// ExtractTo extracts data from *TransformRequestBody into *apidef.TemplateMeta.
func (tr *TransformRequestBody) ExtractTo(meta *apidef.TemplateMeta) {
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

// CachePlugin holds the configuration for the cache plugins.
type CachePlugin struct {
	// Enabled is a boolean flag. If set to `true`, the advanced caching plugin will be enabled.
	Enabled bool `bson:"enabled" json:"enabled"`

	// CacheByRegex defines a regular expression used against the request body to produce a cache key.
	//
	// Example value: `\"id\":[^,]*` (quoted json value).
	CacheByRegex string `bson:"cacheByRegex,omitempty" json:"cacheByRegex,omitempty"`

	// CacheResponseCodes contains a list of valid response codes for responses that are okay to add to the cache.
	CacheResponseCodes []int `bson:"cacheResponseCodes,omitempty" json:"cacheResponseCodes,omitempty"`
}

// Fill fills *CachePlugin from apidef.CacheMeta.
func (a *CachePlugin) Fill(cm apidef.CacheMeta) {
	a.Enabled = !cm.Disabled
	a.CacheByRegex = cm.CacheKeyRegex
	a.CacheResponseCodes = cm.CacheOnlyResponseCodes
}

// ExtractTo extracts *CachePlugin values to *apidef.CacheMeta.
func (a *CachePlugin) ExtractTo(cm *apidef.CacheMeta) {
	cm.Disabled = !a.Enabled
	cm.CacheKeyRegex = a.CacheByRegex
	cm.CacheOnlyResponseCodes = a.CacheResponseCodes
}

// EnforceTimeout holds the configuration for enforcing request timeouts.
type EnforceTimeout struct {
	// Enabled is a boolean flag. If set to `true`, requests will enforce a configured timeout.
	Enabled bool `bson:"enabled" json:"enabled"`

	// Value is the configured timeout in seconds.
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
	// Enabled enables the custom pre plugin.
	Enabled bool `bson:"enabled" json:"enabled"` // required.
	// FunctionName is the name of authentication method.
	FunctionName string `bson:"functionName" json:"functionName"` // required.
	// Path is the path to shared object file in case of gopluign mode or path to js code in case of otto auth plugin.
	Path string `bson:"path" json:"path"` // required.
	// RawBodyOnly if set to true, do not fill body in request or response object.
	RawBodyOnly bool `bson:"rawBodyOnly,omitempty" json:"rawBodyOnly,omitempty"`
	// RequireSession if set to true passes down the session information for plugins after authentication.
	// RequireSession is used only with JSVM custom middleware.
	RequireSession bool `bson:"requireSession,omitempty" json:"requireSession,omitempty"`
}

// CustomPlugins is a list of CustomPlugin.
type CustomPlugins []CustomPlugin

// Fill fills CustomPlugins from supplied Middleware definitions.
func (c CustomPlugins) Fill(mwDefs []apidef.MiddlewareDefinition) {
	for i, mwDef := range mwDefs {
		c[i] = CustomPlugin{
			Enabled:        !mwDef.Disabled,
			Path:           mwDef.Path,
			FunctionName:   mwDef.Name,
			RawBodyOnly:    mwDef.RawBodyOnly,
			RequireSession: mwDef.RequireSession,
		}
	}
}

// ExtractTo extracts CustomPlugins into supplied Middleware definitions.
func (c CustomPlugins) ExtractTo(mwDefs []apidef.MiddlewareDefinition) {
	for i, plugin := range c {
		mwDefs[i] = apidef.MiddlewareDefinition{
			Disabled:       !plugin.Enabled,
			Name:           plugin.FunctionName,
			Path:           plugin.Path,
			RawBodyOnly:    plugin.RawBodyOnly,
			RequireSession: plugin.RequireSession,
		}
	}
}

// PrePlugin configures pre stage plugins.
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
	// Enabled enables virtual endpoint.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Name is the name of js function.
	Name string `bson:"name" json:"name"`
	// Path is the path to js file.
	Path string `bson:"path" json:"path"`
	// Body is the js function to execute encoded in base64 format.
	Body string `bson:"body" json:"body"`
	// ProxyOnError proxies if virtual endpoint errors out.
	ProxyOnError bool `bson:"proxyOnError" json:"proxyOnError"`
	// RequireSession if enabled passes session to virtual endpoint.
	RequireSession bool `bson:"requireSession" json:"requireSession"`
}

// Fill fills *VirtualEndpoint from apidef.VirtualMeta.
func (v *VirtualEndpoint) Fill(meta apidef.VirtualMeta) {
	v.Enabled = !meta.Disabled
	v.Name = meta.ResponseFunctionName
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
	meta.ResponseFunctionName = v.Name
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

type EndpointPostPlugins []EndpointPostPlugin

// EndpointPostPlugin contains endpoint level post plugin configuration.
type EndpointPostPlugin struct {
	// Enabled enables post plugin.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Name is the name of plugin function to be executed.
	Name string `bson:"name" json:"name"`
	// Path is the path to plugin.
	Path string `bson:"path" json:"path"`
}

// Fill fills *EndpointPostPlugin from apidef.GoPluginMeta.
func (e EndpointPostPlugins) Fill(meta apidef.GoPluginMeta) {
	if len(e) == 0 {
		return
	}

	e[0] = EndpointPostPlugin{
		Enabled: !meta.Disabled,
		Name:    meta.SymbolName,
		Path:    meta.PluginPath,
	}
}

// ExtractTo extracts *EndpointPostPlugin to *apidef.GoPluginMeta.
func (e EndpointPostPlugins) ExtractTo(meta *apidef.GoPluginMeta) {
	if len(e) == 0 {
		return
	}

	meta.Disabled = !e[0].Enabled
	meta.PluginPath = e[0].Path
	meta.SymbolName = e[0].Name
}
