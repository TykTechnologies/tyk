package oas

import (
	"net/http"
	"sort"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
)

type Middleware struct {
	// Global contains the configurations related to the global middleware.
	Global *Global `bson:"global,omitempty" json:"global,omitempty"`
	Paths  Paths   `bson:"paths,omitempty" json:"paths,omitempty"`
}

func (m *Middleware) Fill(api apidef.APIDefinition) {
	if m.Global == nil {
		m.Global = &Global{}
	}

	m.Global.Fill(api)
	if ShouldOmit(m.Global) {
		m.Global = nil
	}

	if m.Paths == nil {
		m.Paths = make(Paths)
	}

	m.Paths.Fill(api.VersionData.Versions["Default"].ExtendedPaths)
	if ShouldOmit(m.Paths) {
		m.Paths = nil
	}
}

func (m *Middleware) ExtractTo(api *apidef.APIDefinition) {
	if m.Global != nil {
		m.Global.ExtractTo(api)
	}

	if m.Paths != nil {
		var ep apidef.ExtendedPathsSet
		m.Paths.ExtractTo(&ep)
		defaultVersion := apidef.VersionInfo{UseExtendedPaths: true, ExtendedPaths: ep}
		versions := map[string]apidef.VersionInfo{
			"Default": defaultVersion,
		}

		api.VersionData.Versions = versions
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

type Paths map[string]*Path

func (ps Paths) Fill(ep apidef.ExtendedPathsSet) {
	ps.fillAllowance(ep, allow)
	ps.fillAllowance(ep, block)
	ps.fillAllowance(ep, ignoreAuthentication)
}

func (ps Paths) fillAllowance(ep apidef.ExtendedPathsSet, typ AllowanceType) {
	endpointMetas := ep.WhiteList

	switch typ {
	case block:
		endpointMetas = ep.BlackList
	case ignoreAuthentication:
		endpointMetas = ep.Ignored
	}

	for _, em := range endpointMetas {
		for method := range em.MethodActions {
			if _, ok := ps[em.Path]; !ok {
				ps[em.Path] = &Path{}
			}

			plugins := ps[em.Path].getMethod(method)
			plugins.fillAllowance(em, typ)
		}
	}
}

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

type Path struct {
	Delete  *Plugins `bson:"delete,omitempty" json:"delete,omitempty"`
	Get     *Plugins `bson:"get,omitempty" json:"get,omitempty"`
	Head    *Plugins `bson:"head,omitempty" json:"head,omitempty"`
	Options *Plugins `bson:"options,omitempty" json:"options,omitempty"`
	Patch   *Plugins `bson:"patch,omitempty" json:"patch,omitempty"`
	Post    *Plugins `bson:"post,omitempty" json:"post,omitempty"`
	Put     *Plugins `bson:"put,omitempty" json:"put,omitempty"`
	Trace   *Plugins `bson:"trace,omitempty" json:"trace,omitempty"`
	Connect *Plugins `bson:"connect,omitempty" json:"connect,omitempty"`
}

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

type AllowanceType int

const (
	allow                AllowanceType = 0
	block                AllowanceType = 1
	ignoreAuthentication AllowanceType = 2
)

type Plugins struct {
	Allow                *Allowance `bson:"allow,omitempty" json:"allow,omitempty"`
	Block                *Allowance `bson:"block,omitempty" json:"block,omitempty"`
	IgnoreAuthentication *Allowance `bson:"ignoreAuthentication,omitempty" json:"ignoreAuthentication,omitempty"`
}

func (p *Plugins) fillAllowance(endpointMeta apidef.EndPointMeta, typ AllowanceType) {
	var allowance *Allowance

	switch typ {
	case block:
		if p.Block == nil {
			p.Block = &Allowance{}
		}

		allowance = p.Block
	case ignoreAuthentication:
		if p.IgnoreAuthentication == nil {
			p.IgnoreAuthentication = &Allowance{}
		}

		allowance = p.IgnoreAuthentication
	default:
		if p.Allow == nil {
			p.Allow = &Allowance{}
		}

		allowance = p.Allow
	}

	allowance.Fill(endpointMeta)
	if ShouldOmit(allowance) {
		allowance = nil
	}
}

func (p *Plugins) ExtractTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	p.extractAllowance(ep, path, method, allow)
	p.extractAllowance(ep, path, method, block)
	p.extractAllowance(ep, path, method, ignoreAuthentication)
}

func (p *Plugins) extractAllowance(ep *apidef.ExtendedPathsSet, path string, method string, typ AllowanceType) {
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

	if allowance != nil {
		newPath := true
		for i, em := range *endpointMetas {
			if path == em.Path {
				(*endpointMetas)[i].MethodActions[method] = apidef.EndpointMethodMeta{Action: apidef.NoAction}
				newPath = false
				break
			}
		}

		if newPath {
			methodActions := map[string]apidef.EndpointMethodMeta{
				method: {Action: apidef.NoAction},
			}

			endpointMeta := apidef.EndPointMeta{Path: path, MethodActions: methodActions}
			allowance.ExtractTo(&endpointMeta)
			*endpointMetas = append(*endpointMetas, endpointMeta)
		}
	}
}

type Allowance struct {
	Enabled    bool `bson:"enabled" json:"enabled"`
	IgnoreCase bool `bson:"ignoreCase,omitempty" json:"ignoreCase,omitempty"`
}

func (a *Allowance) Fill(endpointMeta apidef.EndPointMeta) {
	a.Enabled = !endpointMeta.Disabled
	a.IgnoreCase = endpointMeta.IgnoreCase
}

func (a *Allowance) ExtractTo(endpointMeta *apidef.EndPointMeta) {
	endpointMeta.Disabled = !a.Enabled
	endpointMeta.IgnoreCase = a.IgnoreCase
}
