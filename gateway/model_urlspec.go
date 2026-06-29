package gateway

import (
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/regexp"
)

// URLSpec represents a flattened specification for URLs, used to check if a proxy URL
// path is on any of the white, black or ignored lists. This is generated as part of the
// configuration init
type URLSpec struct {
	spec *regexp.Regexp

	metadata    any
	literalPath string
	Status      URLStatus
	matchMode   urlPathMatchMode

	IgnoreCase bool
}

type urlPathMatchMode uint8

const (
	urlPathMatchRegex urlPathMatchMode = iota
	urlPathMatchContains
	urlPathMatchPrefix
	urlPathMatchSuffix
	urlPathMatchExact
)

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

type oasValidateRequestRuntimeMeta struct {
	ValidateRequest *oas.ValidateRequest
	Method          string
	Path            string
	Candidates      []ValidateRequestCandidate
}

type oasMockResponseRuntimeMeta struct {
	MockResponse *oas.MockResponse
	Method       string
	Path         string
	Candidates   []MockResponseCandidate
}

func newOASValidateRequestURLSpec(validateRequest *oas.ValidateRequest, method, path string) URLSpec {
	return URLSpec{
		Status: OASValidateRequest,
		metadata: &oasValidateRequestRuntimeMeta{
			ValidateRequest: validateRequest,
			Method:          method,
			Path:            path,
		},
	}
}

func newOASMockResponseURLSpec(mockResponse *oas.MockResponse, method, path string) URLSpec {
	return URLSpec{
		Status: OASMockResponse,
		metadata: &oasMockResponseRuntimeMeta{
			MockResponse: mockResponse,
			Method:       method,
			Path:         path,
		},
	}
}

func (u *URLSpec) oasValidateRequestRuntimeMeta() (*oasValidateRequestRuntimeMeta, bool) {
	return typedURLSpecMeta[*oasValidateRequestRuntimeMeta](u)
}

func (u *URLSpec) oasMockResponseRuntimeMeta() (*oasMockResponseRuntimeMeta, bool) {
	return typedURLSpecMeta[*oasMockResponseRuntimeMeta](u)
}

func (u *URLSpec) oasPathAndMethod() (path, method string, ok bool) {
	switch u.Status {
	case OASValidateRequest:
		meta, ok := u.oasValidateRequestRuntimeMeta()
		if !ok || meta == nil {
			return "", "", false
		}
		return meta.Path, meta.Method, true
	case OASMockResponse:
		meta, ok := u.oasMockResponseRuntimeMeta()
		if !ok || meta == nil {
			return "", "", false
		}
		return meta.Path, meta.Method, true
	default:
		return "", "", false
	}
}

// modeSpecificSpec returns the respective field of URLSpec if it matches the given mode.
// Deprecated: Usage should not increase.
func (u *URLSpec) modeSpecificSpec(mode URLStatus) (interface{}, bool) {
	switch mode {
	case Ignored, BlackList, WhiteList:
		return nil, true
	case Cached:
		return typedURLSpecMeta[*EndPointCacheMeta](u)
	case Transformed:
		return typedURLSpecMeta[*TransformSpec](u)
	case TransformedJQ:
		return typedURLSpecMeta[*TransformJQSpec](u)
	case HeaderInjected:
		return typedURLSpecMeta[*apidef.HeaderInjectionMeta](u)
	case HeaderInjectedResponse:
		return typedURLSpecMeta[*apidef.HeaderInjectionMeta](u)
	case TransformedResponse:
		return typedURLSpecMeta[*TransformSpec](u)
	case TransformedJQResponse:
		return typedURLSpecMeta[*TransformJQSpec](u)
	case HardTimeout:
		meta, ok := typedURLSpecMeta[*apidef.HardTimeoutMeta](u)
		if !ok {
			return nil, false
		}
		return &meta.TimeOut, true
	case CircuitBreaker:
		return typedURLSpecMeta[*ExtendedCircuitBreakerMeta](u)
	case URLRewrite:
		return urlRewriteRuntimeMetaFromSpec(u)
	case VirtualPath:
		return typedURLSpecMeta[*apidef.VirtualMeta](u)
	case RequestSizeLimit:
		return typedURLSpecMeta[*apidef.RequestSizeMeta](u)
	case MethodTransformed:
		return typedURLSpecMeta[*apidef.MethodTransformMeta](u)
	case RequestTracked:
		return typedURLSpecMeta[*apidef.TrackEndpointMeta](u)
	case RequestNotTracked:
		return typedURLSpecMeta[*apidef.TrackEndpointMeta](u)
	case ValidateJSONRequest:
		return typedURLSpecMeta[*apidef.ValidatePathMeta](u)
	case Internal:
		return typedURLSpecMeta[*apidef.InternalMeta](u)
	case GoPlugin:
		return typedURLSpecMeta[*GoPluginMiddleware](u)
	case PersistGraphQL:
		return typedURLSpecMeta[*apidef.PersistGraphQLMeta](u)
	case RateLimit:
		return typedURLSpecMeta[*apidef.RateLimitMeta](u)
	case OASValidateRequest:
		meta, ok := u.oasValidateRequestRuntimeMeta()
		if !ok || meta == nil {
			return nil, false
		}
		return meta.ValidateRequest, true
	case OASMockResponse:
		meta, ok := u.oasMockResponseRuntimeMeta()
		if !ok || meta == nil {
			return nil, false
		}
		return meta.MockResponse, true
	default:
		return nil, false
	}
}

func urlRewriteRuntimeMetaFromSpec(u *URLSpec) (urlRewriteRuntimeMetadata, bool) {
	if meta, ok := typedURLSpecMeta[*directURLRewriteRuntimeMeta](u); ok {
		return meta, true
	}
	if meta, ok := typedURLSpecMeta[*urlRewriteRuntimeMeta](u); ok {
		return meta, true
	}
	return nil, false
}

func typedURLSpecMeta[T any](u *URLSpec) (T, bool) {
	meta, ok := u.metadata.(T)
	return meta, ok
}

// matchesMethod checks if the given method matches the method required by the URLSpec for the current status.
func (u *URLSpec) matchesMethod(method string) bool {
	switch u.Status {
	case Ignored, BlackList, WhiteList:
		meta, ok := typedURLSpecMeta[*endpointRuntimeMeta](u)
		if !ok {
			return true
		}
		if meta.method != "" {
			return method == meta.method
		}
		if meta.methodActionsByName != nil {
			_, ok := meta.methodActionsByName[method]
			return ok
		}
		return true
	case Cached:
		meta, ok := typedURLSpecMeta[*EndPointCacheMeta](u)
		return ok && (method == meta.Method || (meta.Method == SAFE_METHODS && isSafeMethod(method)))
	case Transformed:
		meta, ok := typedURLSpecMeta[*TransformSpec](u)
		return ok && method == meta.Method
	case TransformedJQ:
		meta, ok := typedURLSpecMeta[*TransformJQSpec](u)
		return ok && method == meta.Method
	case HeaderInjected:
		meta, ok := typedURLSpecMeta[*apidef.HeaderInjectionMeta](u)
		return ok && method == meta.Method
	case HeaderInjectedResponse:
		meta, ok := typedURLSpecMeta[*apidef.HeaderInjectionMeta](u)
		return ok && method == meta.Method
	case TransformedResponse:
		meta, ok := typedURLSpecMeta[*TransformSpec](u)
		return ok && method == meta.Method
	case TransformedJQResponse:
		meta, ok := typedURLSpecMeta[*TransformJQSpec](u)
		return ok && method == meta.Method
	case HardTimeout:
		meta, ok := typedURLSpecMeta[*apidef.HardTimeoutMeta](u)
		return ok && method == meta.Method
	case CircuitBreaker:
		meta, ok := typedURLSpecMeta[*ExtendedCircuitBreakerMeta](u)
		return ok && method == meta.Method
	case URLRewrite:
		meta, ok := urlRewriteRuntimeMetaFromSpec(u)
		return ok && method == meta.urlRewriteMethod()
	case VirtualPath:
		meta, ok := typedURLSpecMeta[*apidef.VirtualMeta](u)
		return ok && method == meta.Method
	case RequestSizeLimit:
		meta, ok := typedURLSpecMeta[*apidef.RequestSizeMeta](u)
		return ok && method == meta.Method
	case MethodTransformed:
		meta, ok := typedURLSpecMeta[*apidef.MethodTransformMeta](u)
		return ok && method == meta.Method
	case RequestTracked:
		meta, ok := typedURLSpecMeta[*apidef.TrackEndpointMeta](u)
		return ok && method == meta.Method
	case RequestNotTracked:
		meta, ok := typedURLSpecMeta[*apidef.TrackEndpointMeta](u)
		return ok && method == meta.Method
	case ValidateJSONRequest:
		meta, ok := typedURLSpecMeta[*apidef.ValidatePathMeta](u)
		return ok && method == meta.Method
	case Internal:
		meta, ok := typedURLSpecMeta[*apidef.InternalMeta](u)
		return ok && method == meta.Method
	case GoPlugin:
		meta, ok := typedURLSpecMeta[*GoPluginMiddleware](u)
		return ok && method == meta.Meta.Method
	case PersistGraphQL:
		meta, ok := typedURLSpecMeta[*apidef.PersistGraphQLMeta](u)
		return ok && method == meta.Method
	case RateLimit:
		meta, ok := typedURLSpecMeta[*apidef.RateLimitMeta](u)
		return ok && method == meta.Method
	case OASValidateRequest, OASMockResponse:
		// OAS middleware is method-specific, check against stored method.
		_, oasMethod, ok := u.oasPathAndMethod()
		return ok && method == oasMethod
	default:
		return false
	}
}

// matchesPath takes the input string and matches it against an internal regex.
// it will match the regex against the clean URL with stripped listen path first,
// then it will match against the full URL including the listen path as provided.
// APISpec to provide URL sanitization of the input is passed along.
func (a *URLSpec) matchesPath(reqPath string, api *APISpec) bool {
	clean := api.StripListenPath(reqPath)
	noVersion := api.StripVersionPath(clean)
	// match /users
	if noVersion != clean && a.matchesPreparedPath(noVersion) {
		return true
	}
	// match /v3/users
	if a.matchesPreparedPath(clean) {
		return true
	}
	// match /listenpath/v3/users
	if a.matchesPreparedPath(reqPath) {
		return true
	}
	return false
}

func (a *URLSpec) matchesPreparedPath(path string) bool {
	switch a.matchMode {
	case urlPathMatchContains:
		return strings.Contains(path, a.literalPath)
	case urlPathMatchPrefix:
		return strings.HasPrefix(path, a.literalPath)
	case urlPathMatchSuffix:
		return strings.HasSuffix(path, a.literalPath)
	case urlPathMatchExact:
		return path == a.literalPath
	default:
		return a.spec != nil && a.spec.MatchString(path)
	}
}
