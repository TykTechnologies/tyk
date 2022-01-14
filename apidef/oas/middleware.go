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

	m.Paths.Fill(api.VersionData.Versions[""].ExtendedPaths)
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
		base := apidef.VersionInfo{UseExtendedPaths: true, ExtendedPaths: ep}
		if api.VersionData.Versions == nil {
			api.VersionData.Versions = make(map[string]apidef.VersionInfo)
		}

		api.VersionData.Versions[""] = base
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
	ps.fillAllowance(ep.WhiteList, allow)
	ps.fillAllowance(ep.BlackList, block)
	ps.fillAllowance(ep.Ignored, ignoreAuthentication)
	ps.fillMockResponse(ep.MockResponse)
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

func (ps Paths) fillMockResponse(mockMetas []apidef.MockResponseMeta) {
	for _, mm := range mockMetas {
		if _, ok := ps[mm.Path]; !ok {
			ps[mm.Path] = &Path{}
		}

		plugins := ps[mm.Path].getMethod(mm.Method)
		if plugins.MockResponse == nil {
			plugins.MockResponse = &MockResponse{}
		}

		plugins.MockResponse.Fill(mm)
		if ShouldOmit(plugins.MockResponse) {
			plugins.MockResponse = nil
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
	// MockResponse allows you to mock responses for an API endpoint.
	MockResponse *MockResponse `bson:"mockResponse,omitempty" json:"mockResponse,omitempty"`
	// TransformRequestMethod allows you to transform the method of a request.
	TransformRequestMethod *TransformRequestMethod `bson:"transformRequestMethod,omitempty" json:"transformRequestMethod,omitempty"`
	Cache                  *CachePlugin            `bson:"cache,omitempty" json:"cache,omitempty"`
	EnforceTimeout         *EnforceTimeout         `bson:"enforcedTimeout,omitempty" json:"enforcedTimeout,omitempty"`
}

func (p *Plugins) ExtractTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	p.extractAllowanceTo(ep, path, method, allow)
	p.extractAllowanceTo(ep, path, method, block)
	p.extractAllowanceTo(ep, path, method, ignoreAuthentication)
	p.extractMockResponseTo(ep, path, method)
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

func (p *Plugins) extractMockResponseTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if p.MockResponse == nil {
		return
	}

	mockMeta := apidef.MockResponseMeta{Path: path, Method: method}
	p.MockResponse.ExtractTo(&mockMeta)
	ep.MockResponse = append(ep.MockResponse, mockMeta)
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

type MockResponse struct {
	// Enabled enables Mock response in the given path and method.
	Enabled bool `bson:"enabled" json:"enabled"`
	// IgnoreCase ignores case while matching incoming request path.
	IgnoreCase bool `bson:"ignoreCase,omitempty" json:"ignoreCase,omitempty"`
	// Code is the mock response's http response code that will be returned to client.
	Code int `bson:"code" json:"code"`
	// Body is the mock response's body that will be returned to client.
	Body string `bson:"body" json:"body"`
	// Headers is the mock response's headers that will be returned to client.
	Headers []Header `bson:"headers,omitempty" json:"headers,omitempty"`
}

func (mr *MockResponse) Fill(mockMeta apidef.MockResponseMeta) {
	mr.Enabled = !mockMeta.Disabled
	mr.IgnoreCase = mockMeta.IgnoreCase
	mr.Code = mockMeta.Code
	mr.Body = mockMeta.Body
	mr.Headers = []Header{}
	for name, value := range mockMeta.Headers {
		mr.Headers = append(mr.Headers, Header{Name: name, Value: value})
	}

	sort.Slice(mr.Headers, func(i, j int) bool {
		return mr.Headers[i].Name < mr.Headers[j].Name
	})

	if len(mr.Headers) == 0 {
		mr.Headers = nil
	}
}

func (mr *MockResponse) ExtractTo(mockMeta *apidef.MockResponseMeta) {
	mockMeta.Disabled = !mr.Enabled
	mockMeta.IgnoreCase = mr.IgnoreCase
	mockMeta.Code = mr.Code
	mockMeta.Body = mr.Body
	mockMeta.Headers = make(map[string]string)
	for _, h := range mr.Headers {
		mockMeta.Headers[h.Name] = h.Value
	}
}

type Header struct {
	Name  string `bson:"name" json:"name"`
	Value string `bson:"value" json:"value"`
}

type TransformRequestMethod struct {
	// Enabled enables Method Transform for the given path and method.
	Enabled bool `bson:"enabled" json:"enabled"`
	// ToMethod is the http method value to which the method of an incoming request will be transformed.
	ToMethod string `bson:"toMethod" json:"toMethod"`
}

func (tm *TransformRequestMethod) Fill(meta apidef.MethodTransformMeta) {
	tm.Enabled = !meta.Disabled
	tm.ToMethod = meta.ToMethod
}

func (tm *TransformRequestMethod) ExtractTo(meta *apidef.MethodTransformMeta) {
	meta.Disabled = !tm.Enabled
	meta.ToMethod = tm.ToMethod
}

type CachePlugin struct {
	Enabled            bool   `bson:"enabled" json:"enabled"`
	CacheByRegex       string `bson:"cacheByRegex,omitempty" json:"cacheByRegex,omitempty"`
	CacheResponseCodes []int  `bson:"cacheResponseCodes,omitempty" json:"cacheResponseCodes,omitempty"`
}

func (a *CachePlugin) Fill(cm apidef.CacheMeta) {
	a.Enabled = !cm.Disabled
	a.CacheByRegex = cm.CacheKeyRegex
	a.CacheResponseCodes = cm.CacheOnlyResponseCodes
}

func (a *CachePlugin) ExtractTo(cm *apidef.CacheMeta) {
	cm.Disabled = !a.Enabled
	cm.CacheKeyRegex = a.CacheByRegex
	cm.CacheOnlyResponseCodes = a.CacheResponseCodes
}

type EnforceTimeout struct {
	Enabled bool `bson:"enabled" json:"enabled"`
	Value   int  `bson:"value" json:"value"`
}

func (et *EnforceTimeout) Fill(meta apidef.HardTimeoutMeta) {
	et.Enabled = !meta.Disabled
	et.Value = meta.TimeOut
}

func (et *EnforceTimeout) ExtractTo(meta *apidef.HardTimeoutMeta) {
	meta.Disabled = !et.Enabled
	meta.TimeOut = et.Value
}
