package gateway

import (
	"net/url"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/regexp"
)

var oasPathParamRegex = regexp.MustCompile(`\{([^}]+)\}`)

// oasExactPath is an OAS path template compiled to an anchored regex with one
// capture group per path parameter. It is enabled only on allow and
// ignoreAuthentication entries; a template that fails to compile never matches.
type oasExactPath struct {
	enabled bool
	re      *regexp.Regexp
	err     error
	params  []string
}

// quoteOASPathLiteral quotes a literal part of an OAS path template, keeping
// the mux wildcards the way httputil.PreparePathRegexp reads them: "/*/" is
// one segment, a trailing "/*" is the rest of the path.
func quoteOASPathLiteral(literal string) string {
	quoted := regexp.QuoteMeta(strings.ReplaceAll(literal, "%", "%25"))
	quoted = strings.ReplaceAll(quoted, `/\*/`, "/[^/]+/")
	quoted = strings.ReplaceAll(quoted, `/\*`, "/.*")
	return quoted
}

// newOASExactPath compiles the template; a trailing slash on the request path
// is tolerated. A compile failure is logged once, here.
func newOASExactPath(template string, ignoreCase bool) oasExactPath {
	var (
		b      strings.Builder
		params []string
		last   int
	)

	if ignoreCase {
		b.WriteString("(?i)")
	}
	b.WriteString("^")

	for _, m := range oasPathParamRegex.FindAllStringSubmatchIndex(template, -1) {
		b.WriteString(quoteOASPathLiteral(template[last:m[0]]))
		b.WriteString("([^/]+)")
		params = append(params, template[m[2]:m[3]])
		last = m[1]
	}

	b.WriteString(quoteOASPathLiteral(template[last:]))
	b.WriteString("/?$")

	re, err := regexp.Compile(b.String())
	if err != nil {
		log.WithError(err).Errorf("OAS path %q: cannot compile exact matcher, requests to it will be denied", template)
	}

	return oasExactPath{enabled: true, re: re, err: err, params: params}
}

// oasMatchPath returns the request path decoded segment by segment, so a
// non-ASCII listen path or template literal matches as written while an
// encoded slash stays inside its parameter value.
func oasMatchPath(u *url.URL) string {
	segments := strings.Split(u.EscapedPath(), "/")
	for i, segment := range segments {
		decoded, err := url.PathUnescape(segment)
		if err != nil {
			continue
		}
		decoded = strings.ReplaceAll(decoded, "%", "%25")
		segments[i] = strings.ReplaceAll(decoded, "/", "%2F")
	}
	return strings.Join(segments, "/")
}

// matches returns the path parameter values when path is exactly the template.
func (p *oasExactPath) matches(path string) (map[string]string, bool) {
	if !p.enabled || p.err != nil {
		return nil, false
	}

	m := p.re.FindStringSubmatch(path)
	if m == nil {
		return nil, false
	}

	params := make(map[string]string, len(p.params))
	for i, name := range p.params {
		value, err := url.PathUnescape(m[i+1])
		if err != nil {
			value = m[i+1]
		}
		params[name] = value
	}

	return params, true
}

// URLSpec represents a flattened specification for URLs, used to check if a proxy URL
// path is on any of the white, black or ignored lists. This is generated as part of the
// configuration init
type URLSpec struct {
	spec *regexp.Regexp
	// oasExact is the OAS path template behind an allow or ignoreAuthentication
	// entry, used to grant only the declared operation. Disabled for other entries.
	oasExact oasExactPath

	Status                    URLStatus
	MethodActions             map[string]apidef.EndpointMethodMeta
	Whitelist                 apidef.EndPointMeta
	Blacklist                 apidef.EndPointMeta
	Ignored                   apidef.EndPointMeta
	MockResponse              apidef.MockResponseMeta
	CacheConfig               EndPointCacheMeta
	TransformAction           TransformSpec
	TransformResponseAction   TransformSpec
	TransformJQAction         TransformJQSpec
	TransformJQResponseAction TransformJQSpec
	InjectHeaders             apidef.HeaderInjectionMeta
	InjectHeadersResponse     apidef.HeaderInjectionMeta
	HardTimeout               apidef.HardTimeoutMeta
	CircuitBreaker            ExtendedCircuitBreakerMeta
	URLRewrite                *apidef.URLRewriteMeta
	VirtualPathSpec           apidef.VirtualMeta
	RequestSize               apidef.RequestSizeMeta
	MethodTransform           apidef.MethodTransformMeta
	TrackEndpoint             apidef.TrackEndpointMeta
	DoNotTrackEndpoint        apidef.TrackEndpointMeta
	ValidatePathMeta          apidef.ValidatePathMeta
	Internal                  apidef.InternalMeta
	GoPluginMeta              GoPluginMiddleware
	PersistGraphQL            apidef.PersistGraphQLMeta
	RateLimit                 apidef.RateLimitMeta
	OASValidateRequestMeta    *oas.ValidateRequest
	OASMockResponseMeta       *oas.MockResponse

	// OASValidateRequestCandidates holds multiple OAS endpoints that compile to the
	// same regex pattern. When non-empty, the validate request middleware must
	// disambiguate by checking path parameter schemas against each candidate.
	OASValidateRequestCandidates []ValidateRequestCandidate

	// OASMockResponseCandidates holds multiple OAS endpoints that compile to the
	// same regex pattern. When non-empty, the mock response middleware must
	// disambiguate by checking path parameter schemas against each candidate.
	OASMockResponseCandidates []MockResponseCandidate

	IgnoreCase bool
	// OASMethod stores the HTTP method for OAS-specific middleware
	// This is needed because OAS operations are method-specific
	OASMethod string
	// OASPath stores the original OAS path pattern (e.g., "/users/{id}")
	// This is used for matching against the OAS router when needed
	OASPath string
}

// ValidateRequestCandidate represents one OAS endpoint that maps to the same
// compiled regex pattern. Used for disambiguation when multiple parameterized
// paths collapse to the same regex (e.g., /employees/{prct} and /employees/{zd}).
type ValidateRequestCandidate struct {
	OASValidateRequestMeta *oas.ValidateRequest
	OASMethod              string
	OASPath                string
}

// MockResponseCandidate represents one OAS endpoint that maps to the same
// compiled regex pattern for mock response disambiguation.
type MockResponseCandidate struct {
	OASMockResponseMeta *oas.MockResponse
	OASMethod           string
	OASPath             string
}

// modeSpecificSpec returns the respective field of URLSpec if it matches the given mode.
// Deprecated: Usage should not increase.
func (u *URLSpec) modeSpecificSpec(mode URLStatus) (interface{}, bool) {
	switch mode {
	case Ignored, BlackList, WhiteList:
		return nil, true
	case Cached:
		return &u.CacheConfig, true
	case Transformed:
		return &u.TransformAction, true
	case TransformedJQ:
		return &u.TransformJQAction, true
	case HeaderInjected:
		return &u.InjectHeaders, true
	case HeaderInjectedResponse:
		return &u.InjectHeadersResponse, true
	case TransformedResponse:
		return &u.TransformResponseAction, true
	case TransformedJQResponse:
		return &u.TransformJQResponseAction, true
	case HardTimeout:
		return &u.HardTimeout.TimeOut, true
	case CircuitBreaker:
		return &u.CircuitBreaker, true
	case URLRewrite:
		return u.URLRewrite, true
	case VirtualPath:
		return &u.VirtualPathSpec, true
	case RequestSizeLimit:
		return &u.RequestSize, true
	case MethodTransformed:
		return &u.MethodTransform, true
	case RequestTracked:
		return &u.TrackEndpoint, true
	case RequestNotTracked:
		return &u.DoNotTrackEndpoint, true
	case ValidateJSONRequest:
		return &u.ValidatePathMeta, true
	case Internal:
		return &u.Internal, true
	case GoPlugin:
		return &u.GoPluginMeta, true
	case PersistGraphQL:
		return &u.PersistGraphQL, true
	case OASValidateRequest:
		return u.OASValidateRequestMeta, true
	case OASMockResponse:
		return u.OASMockResponseMeta, true
	default:
		return nil, false
	}
}

// matchesMethod checks if the given method matches the method required by the URLSpec for the current status.
func (u *URLSpec) matchesMethod(method string) bool {
	switch u.Status {
	case Ignored, BlackList, WhiteList:
		return true
	case Cached:
		return method == u.CacheConfig.Method || (u.CacheConfig.Method == SAFE_METHODS && isSafeMethod(method))
	case Transformed:
		return method == u.TransformAction.Method
	case TransformedJQ:
		return method == u.TransformJQAction.Method
	case HeaderInjected:
		return method == u.InjectHeaders.Method
	case HeaderInjectedResponse:
		return method == u.InjectHeadersResponse.Method
	case TransformedResponse:
		return method == u.TransformResponseAction.Method
	case TransformedJQResponse:
		return method == u.TransformJQResponseAction.Method
	case HardTimeout:
		return method == u.HardTimeout.Method
	case CircuitBreaker:
		return method == u.CircuitBreaker.Method
	case URLRewrite:
		return method == u.URLRewrite.Method
	case VirtualPath:
		return method == u.VirtualPathSpec.Method
	case RequestSizeLimit:
		return method == u.RequestSize.Method
	case MethodTransformed:
		return method == u.MethodTransform.Method
	case RequestTracked:
		return method == u.TrackEndpoint.Method
	case RequestNotTracked:
		return method == u.DoNotTrackEndpoint.Method
	case ValidateJSONRequest:
		return method == u.ValidatePathMeta.Method
	case Internal:
		return method == u.Internal.Method
	case GoPlugin:
		return method == u.GoPluginMeta.Meta.Method
	case PersistGraphQL:
		return method == u.PersistGraphQL.Method
	case RateLimit:
		return method == u.RateLimit.Method
	case OASValidateRequest, OASMockResponse:
		// OAS middleware is method-specific, check against stored method
		return method == u.OASMethod
	default:
		return false
	}
}

// matchesPath matches the request path against the internal regex the way
// the API's endpointMatcher prescribes.
func (a *URLSpec) matchesPath(reqPath string, api *APISpec) bool {
	return api.endpointMatcher.matchesPath(a, reqPath, api)
}
