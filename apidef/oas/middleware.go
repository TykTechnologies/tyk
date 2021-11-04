package oas

import (
	"github.com/TykTechnologies/tyk/apidef"
)

type Middleware struct {
	// Global contains the configurations related to the global middleware.
	Global *Global `bson:"global,omitempty" json:"global,omitempty"`
}

func (m *Middleware) Fill(api apidef.APIDefinition) {
	if m.Global == nil {
		m.Global = &Global{}
	}

	m.Global.Fill(api)
	if ShouldOmit(m.Global) {
		m.Global = nil
	}
}

func (m *Middleware) ExtractTo(api *apidef.APIDefinition) {
	if m.Global != nil {
		m.Global.ExtractTo(api)
	}
}

type Global struct {
	CORS *CORS `bson:"cors,omitempty" json:"cors,omitempty"`
	// Cache contains the configurations related to caching.
	// Old API Definition: `cache_options`
	Cache *Cache `bson:"cache,omitempty" json:"cache,omitempty"`
}

func (g *Global) Fill(api apidef.APIDefinition) {
	// CORS
	if g.CORS == nil {
		g.CORS = &CORS{}
	}

	g.CORS.Fill(api.CORS)
	if ShouldOmit(g.CORS) {
		g.CORS = nil
	}

	// Cache
	if g.Cache == nil {
		g.Cache = &Cache{}
	}

	g.Cache.Fill(api.CacheOptions)
	if ShouldOmit(g.Cache) {
		g.Cache = nil
	}
}

func (g *Global) ExtractTo(api *apidef.APIDefinition) {
	if g.CORS != nil {
		g.CORS.ExtractTo(&api.CORS)
	}

	if g.Cache != nil {
		g.Cache.ExtractTo(&api.CacheOptions)
	}
}

type CORS struct {
	Enabled            bool     `bson:"enabled" json:"enabled"` // required
	MaxAge             int      `bson:"maxAge,omitempty" json:"maxAge,omitempty"`
	AllowCredentials   bool     `bson:"allowCredentials,omitempty" json:"allowCredentials,omitempty"`
	ExposedHeaders     []string `bson:"exposedHeaders,omitempty" json:"exposedHeaders,omitempty"`
	AllowedHeaders     []string `bson:"allowedHeaders,omitempty" json:"allowedHeaders,omitempty"`
	OptionsPassthrough bool     `bson:"optionsPassthrough,omitempty" json:"optionsPassthrough,omitempty"`
	Debug              bool     `bson:"debug,omitempty" json:"debug,omitempty"`
	AllowedOrigins     []string `bson:"allowedOrigins,omitempty" json:"allowedOrigins,omitempty"`
	AllowedMethods     []string `bson:"allowedMethods,omitempty" json:"allowedMethods,omitempty"`
}

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

type Cache struct {
	// Enabled turns global cache middleware on or off. It is still possible to enable caching on a per-path basis
	// by explicitly setting the endpoint cache middleware.
	// Old API Definition: `cache_options.enable_cache`
	Enabled bool `bson:"enabled" json:"enabled"` // required
	// Timeout is the TTL for a cached object in seconds.
	// Old API Definition: `cache_options.cache_timeout`
	Timeout int64 `bson:"timeout,omitempty" json:"timeout,omitempty"`
	// CacheAllSafeRequests caches responses to (`GET`, `HEAD`, `OPTIONS`) requests overrides per-path cache settings in versions,
	// applies across versions.
	// Old API Definition: `cache_options.cache_all_safe_requests`
	CacheAllSafeRequests bool `bson:"cacheAllSafeRequests,omitempty" json:"cacheAllSafeRequests,omitempty"`
	// CacheResponseCodes is an array of response codes which are safe to cache e.g. `404`.
	// Old API Definition: `cache_options.cache_response_codes`
	CacheResponseCodes []int `bson:"cacheResponseCodes,omitempty" json:"cacheResponseCodes,omitempty"`
	// CacheByHeaders allows header values to be used as part of the cache key.
	// Old API Definition: `cache_options.cache_by_headers`
	CacheByHeaders []string `bson:"cacheByHeaders,omitempty" json:"cacheByHeaders,omitempty"`
	// EnableUpstreamCacheControl instructs Tyk Cache to respect upstream cache control headers.
	// Old API Definition: `cache_options.enable_upstream_cache_control`
	EnableUpstreamCacheControl bool `bson:"enableUpstreamCacheControl,omitempty" json:"enableUpstreamCacheControl,omitempty"`
	// ControlTTLHeaderName is the response header which tells Tyk how long it is safe to cache the response for.
	// Old API Definition: `cache_options.cache_control_ttl_header`
	ControlTTLHeaderName string `bson:"controlTTLHeaderName,omitempty" json:"controlTTLHeaderName,omitempty"`
}

func (c *Cache) Fill(cache apidef.CacheOptions) {
	c.Enabled = cache.EnableCache
	c.Timeout = cache.CacheTimeout
	c.CacheAllSafeRequests = cache.CacheAllSafeRequests
	c.CacheResponseCodes = cache.CacheOnlyResponseCodes
	c.CacheByHeaders = cache.CacheByHeaders
	c.EnableUpstreamCacheControl = cache.EnableUpstreamCacheControl
	c.ControlTTLHeaderName = cache.CacheControlTTLHeader
}

func (c *Cache) ExtractTo(cache *apidef.CacheOptions) {
	cache.EnableCache = c.Enabled
	cache.CacheTimeout = c.Timeout
	cache.CacheAllSafeRequests = c.CacheAllSafeRequests
	cache.CacheOnlyResponseCodes = c.CacheResponseCodes
	cache.CacheByHeaders = c.CacheByHeaders
	cache.EnableUpstreamCacheControl = c.EnableUpstreamCacheControl
	cache.CacheControlTTLHeader = c.ControlTTLHeaderName
}
