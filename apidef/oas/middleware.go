package oas

import (
	"reflect"

	"github.com/TykTechnologies/tyk/apidef"
)

type Middleware struct {
	Global *Global `bson:"global,omitempty" json:"global,omitempty"`
}

func (m *Middleware) Fill(api apidef.APIDefinition) {
	if m.Global == nil {
		m.Global = &Global{}
	}

	m.Global.Fill(api)
	if reflect.DeepEqual(m.Global, &Global{}) {
		m.Global = nil
	}
}

func (m *Middleware) ExtractTo(api *apidef.APIDefinition) {
	if m.Global != nil {
		m.Global.ExtractTo(api)
	}
}

type Global struct {
	CORS  *CORS  `bson:"cors,omitempty" json:"cors,omitempty"`
	Cache *Cache `bson:"cache,omitempty" json:"cache,omitempty"`
}

func (g *Global) Fill(api apidef.APIDefinition) {
	// CORS
	if g.CORS == nil {
		g.CORS = &CORS{}
	}

	g.CORS.Fill(api.CORS)
	if reflect.DeepEqual(g.CORS, &CORS{}) {
		g.CORS = nil
	}

	// Cache
	if g.Cache == nil {
		g.Cache = &Cache{}
	}

	g.Cache.Fill(api.CacheOptions)
	if reflect.DeepEqual(g.Cache, &Cache{}) {
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
	Enabled                    bool     `bson:"enabled" json:"enabled"` // required
	Timeout                    int64    `bson:"timeout,omitempty" json:"timeout,omitempty"`
	CacheAllSafeRequests       bool     `bson:"cacheAllSafeRequests,omitempty" json:"cacheAllSafeRequests,omitempty"`
	CacheResponseCodes         []int    `bson:"cacheResponseCodes,omitempty" json:"cacheResponseCodes,omitempty"`
	CacheByHeaders             []string `bson:"cacheByHeaders,omitempty" json:"cacheByHeaders,omitempty"`
	EnableUpstreamCacheControl bool     `bson:"enableUpstreamCacheControl,omitempty" json:"enableUpstreamCacheControl,omitempty"`
	ControlTTLHeaderName       string   `bson:"controlTTLHeaderName,omitempty" json:"controlTTLHeaderName,omitempty"`
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
