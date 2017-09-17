package apispec

import (
	"regexp"
	"github.com/rubyist/circuitbreaker"
	"net/url"
	"strings"
	"time"
	"github.com/TykTechnologies/tyk/apidef"
	textTemplate "text/template"

	"github.com/TykTechnologies/tyk/config"
	"net/http"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/load_balancer"
	"github.com/TykTechnologies/tyk/jsvm"
	"github.com/TykTechnologies/tyk/health"
	logger "github.com/TykTechnologies/tyk/log"
	"github.com/TykTechnologies/tyk/tykctx"
	"github.com/TykTechnologies/tyk/session_handler"
	"github.com/TykTechnologies/tyk/authorization_handler"
)

const (
	LDAPStorageEngine apidef.StorageEngineCode = "ldap"
	RPCStorageEngine  apidef.StorageEngineCode = "rpc"
)

var log = logger.Get()

// URLStatus is a custom enum type to avoid collisions
type URLStatus int

// Enums representing the various statuses for a VersionInfo Path match during a
// proxy request
const (
	_ URLStatus = iota
	Ignored
	WhiteList
	BlackList
	Cached
	Transformed
	HeaderInjected
	HeaderInjectedResponse
	TransformedResponse
	HardTimeout
	CircuitBreaker
	URLRewrite
	VirtualPath
	RequestSizeLimit
	MethodTransformed
	RequestTracked
	RequestNotTracked
)

// RequestStatus is a custom type to avoid collisions
type RequestStatus string

// Statuses of the request, all are false-y except StatusOk and StatusOkAndIgnore
const (
	VersionNotFound                RequestStatus = "Version information not found"
	VersionDoesNotExist            RequestStatus = "This API version does not seem to exist"
	VersionWhiteListStatusNotFound RequestStatus = "WhiteListStatus for path not found"
	VersionExpired                 RequestStatus = "Api Version has expired, please check documentation or contact administrator"
	EndPointNotAllowed             RequestStatus = "Requested endpoint is forbidden"
	StatusOkAndIgnore              RequestStatus = "Everything OK, passing and not filtering"
	StatusOk                       RequestStatus = "Everything OK, passing"
	StatusCached                   RequestStatus = "Cached path"
	StatusTransform                RequestStatus = "Transformed path"
	StatusTransformResponse        RequestStatus = "Transformed response"
	StatusHeaderInjected           RequestStatus = "Header injected"
	StatusMethodTransformed        RequestStatus = "Method Transformed"
	StatusHeaderInjectedResponse   RequestStatus = "Header injected on response"
	StatusRedirectFlowByReply      RequestStatus = "Exceptional action requested, redirecting flow!"
	StatusHardTimeout              RequestStatus = "Hard Timeout enforced on path"
	StatusCircuitBreaker           RequestStatus = "Circuit breaker enforced"
	StatusURLRewrite               RequestStatus = "URL Rewritten"
	StatusVirtualPath              RequestStatus = "Virtual Endpoint"
	StatusRequestSizeControlled    RequestStatus = "Request Size Limited"
	StatusRequesTracked            RequestStatus = "Request Tracked"
	StatusRequestNotTracked        RequestStatus = "Request Not Tracked"
)

// URLSpec represents a flattened specification for URLs, used to check if a proxy URL
// path is on any of the white, plack or ignored lists. This is generated as part of the
// configuration init
type URLSpec struct {
	Spec                    *regexp.Regexp
	Status                  URLStatus
	MethodActions           map[string]apidef.EndpointMethodMeta
	TransformAction         TransformSpec
	TransformResponseAction TransformSpec
	InjectHeaders           apidef.HeaderInjectionMeta
	InjectHeadersResponse   apidef.HeaderInjectionMeta
	HardTimeout             apidef.HardTimeoutMeta
	CircuitBreaker          ExtendedCircuitBreakerMeta
	URLRewrite              apidef.URLRewriteMeta
	VirtualPathSpec         apidef.VirtualMeta
	RequestSize             apidef.RequestSizeMeta
	MethodTransform         apidef.MethodTransformMeta
	TrackEndpoint           apidef.TrackEndpointMeta
	DoNotTrackEndpoint      apidef.TrackEndpointMeta
}

type TransformSpec struct {
	apidef.TemplateMeta
	Template *textTemplate.Template
}

type ExtendedCircuitBreakerMeta struct {
	apidef.CircuitBreakerMeta
	CB *circuit.Breaker
}

// APISpec represents a path specification for an API, to avoid enumerating multiple nested lists, a single
// flattened URL list is checked for matching paths and then it's status evaluated if found.
type APISpec struct {
	*apidef.APIDefinition

	RxPaths           map[string][]URLSpec
	WhiteListEnabled  map[string]bool
	Target            *url.URL
	AuthManager       authorization_handler.AuthorisationHandler
	SessionManager    session_handler.SessionHandler
	OAuthManager      *OAuthManager
	OrgSessionManager session_handler.SessionHandler
	EventPaths        map[apidef.TykEvent][]config.TykEventHandler
	Health            health.HealthChecker
	JSVM              jsvm.JSVM
	ResponseChain     []TykResponseHandler
	RoundRobin        load_balancer.RoundRobin
	URLRewriteEnabled bool
	CircuitBreakerEnabled    bool
	EnforcedTimeoutEnabled   bool
	LastGoodHostList         *apidef.HostList
	HasRun                   bool
	ServiceRefreshInProgress bool
	FireEventFunc func(name apidef.TykEvent, meta interface{}, handlers map[apidef.TykEvent][]config.TykEventHandler)
}

func (a *APISpec) Init(authStore, sessionStore, healthStore, orgStore storage.StorageHandler, conf *config.Config) {
	a.AuthManager.Init(authStore)
	a.SessionManager.Init(sessionStore, conf)
	a.Health.Init(healthStore)
	a.OrgSessionManager.Init(orgStore, conf)
}

func (a *APISpec) getURLStatus(stat URLStatus) RequestStatus {
	switch stat {
	case Ignored:
		return StatusOkAndIgnore
	case BlackList:
		return EndPointNotAllowed
	case WhiteList:
		return StatusOk
	case Cached:
		return StatusCached
	case Transformed:
		return StatusTransform
	case HeaderInjected:
		return StatusHeaderInjected
	case HeaderInjectedResponse:
		return StatusHeaderInjectedResponse
	case TransformedResponse:
		return StatusTransformResponse
	case HardTimeout:
		return StatusHardTimeout
	case CircuitBreaker:
		return StatusCircuitBreaker
	case URLRewrite:
		return StatusURLRewrite
	case VirtualPath:
		return StatusVirtualPath
	case RequestSizeLimit:
		return StatusRequestSizeControlled
	case MethodTransformed:
		return StatusMethodTransformed
	case RequestTracked:
		return StatusRequesTracked
	case RequestNotTracked:
		return StatusRequestNotTracked
	default:
		log.Error("URL Status was not one of Ignored, Blacklist or WhiteList! Blocking.")
		return EndPointNotAllowed
	}
}

// IsURLAllowedAndIgnored checks if a url is allowed and ignored.
func (a *APISpec) IsURLAllowedAndIgnored(r *http.Request, rxPaths []URLSpec, whiteListStatus bool) (RequestStatus, interface{}) {
	// Check if ignored
	for _, v := range rxPaths {
		if !v.Spec.MatchString(strings.ToLower(r.URL.Path)) {
			continue
		}
		if v.MethodActions != nil {
			// We are using an extended path set, check for the method
			methodMeta, matchMethodOk := v.MethodActions[r.Method]
			if matchMethodOk {
				// Matched the method, check what status it is:
				if methodMeta.Action == apidef.NoAction {
					// NoAction status means we're not treating this request in any special or exceptional way
					return a.getURLStatus(v.Status), nil
				}
				// TODO: Extend here for additional reply options
				switch methodMeta.Action {
				case apidef.Reply:
					return StatusRedirectFlowByReply, &methodMeta
				default:
					log.Error("URL Method Action was not set to NoAction, blocking.")
					return EndPointNotAllowed, nil
				}
			}

			if whiteListStatus {
				// We have a whitelist, nothing gets through unless specifically defined
				return EndPointNotAllowed, nil
			}

			// Method not matched in an extended set, means it can be passed through
			return StatusOk, nil
		}

		if v.TransformAction.Template != nil {
			return a.getURLStatus(v.Status), &v.TransformAction
		}

		// TODO: Fix, Not a great detection method
		if len(v.InjectHeaders.Path) > 0 {
			return a.getURLStatus(v.Status), &v.InjectHeaders
		}

		// Using a legacy path, handle it raw.
		return a.getURLStatus(v.Status), nil
	}

	// Nothing matched - should we still let it through?
	if whiteListStatus {
		// We have a whitelist, nothing gets through unless specifically defined
		return EndPointNotAllowed, nil
	}

	// No whitelist, but also not in any of the other lists, let it through and filter
	return StatusOk, nil
}

// CheckSpecMatchesStatus checks if a url spec has a specific status
func (a *APISpec) CheckSpecMatchesStatus(r *http.Request, rxPaths []URLSpec, mode URLStatus) (bool, interface{}) {
	// Check if ignored
	for _, v := range rxPaths {
		match := v.Spec.MatchString(r.URL.Path)
		// only return it it's what we are looking for
		if !match || mode != v.Status {
			continue
		}
		switch v.Status {
		case Ignored, BlackList, WhiteList, Cached:
			return true, nil
		case Transformed:
			if r.Method == v.TransformAction.Method {
				return true, &v.TransformAction
			}
		case HeaderInjected:
			if r.Method == v.InjectHeaders.Method {
				return true, &v.InjectHeaders
			}
		case HeaderInjectedResponse:
			if r.Method == v.InjectHeadersResponse.Method {
				return true, &v.InjectHeadersResponse
			}
		case TransformedResponse:
			if r.Method == v.TransformResponseAction.Method {
				return true, &v.TransformResponseAction
			}
		case HardTimeout:
			if r.Method == v.HardTimeout.Method {
				return true, &v.HardTimeout.TimeOut
			}
		case CircuitBreaker:
			if r.Method == v.CircuitBreaker.Method {
				return true, &v.CircuitBreaker
			}
		case URLRewrite:
			if r.Method == v.URLRewrite.Method {
				return true, &v.URLRewrite
			}
		case VirtualPath:
			if r.Method == v.VirtualPathSpec.Method {
				return true, &v.VirtualPathSpec
			}
		case RequestSizeLimit:
			if r.Method == v.RequestSize.Method {
				return true, &v.RequestSize
			}
		case MethodTransformed:
			if r.Method == v.MethodTransform.Method {
				return true, &v.MethodTransform
			}
		case RequestTracked:
			if r.Method == v.TrackEndpoint.Method {
				return true, &v.TrackEndpoint
			}
		case RequestNotTracked:
			if r.Method == v.DoNotTrackEndpoint.Method {
				return true, &v.DoNotTrackEndpoint
			}
		}
	}
	return false, nil
}

func (a *APISpec) GetVersionFromRequest(r *http.Request) string {
	switch a.VersionDefinition.Location {
	case "header":
		return r.Header.Get(a.VersionDefinition.Key)

	case "url-param":
		return r.URL.Query().Get(a.VersionDefinition.Key)

	case "url":
		url := strings.Replace(r.URL.Path, a.Proxy.ListenPath, "", 1)
		// First non-empty part of the path is the version ID
		for _, part := range strings.Split(url, "/") {
			if part != "" {
				return part
			}
		}
	}
	return ""
}

// IsThisAPIVersionExpired checks if an API version (during a proxied
// request) is expired. If it isn't and the configured time was valid,
// it also returns the expiration time.
func (a *APISpec) IsThisAPIVersionExpired(versionDef *apidef.VersionInfo) (bool, *time.Time) {
	// Never expires
	if versionDef.Expires == "" || versionDef.Expires == "-1" {
		return false, nil
	}

	// otherwise - calculate the time
	t, err := time.Parse("2006-01-02 15:04", versionDef.Expires)
	if err != nil {
		log.Error("Could not parse expiry date for API, dissallow: ", err)
		return true, nil
	}

	// It's in the past, expire
	// It's in the future, keep going
	return time.Since(t) >= 0, &t
}

// IsRequestValid will check if an incoming request has valid version
// data and return a RequestStatus that describes the status of the
// request
func (a *APISpec) IsRequestValid(r *http.Request) (bool, RequestStatus, interface{}) {
	versionMetaData, versionPaths, whiteListStatus, stat := a.Version(r)

	// Screwed up version info - fail and pass through
	if stat != StatusOk {
		return false, stat, nil
	}

	// Is the API version expired?
	// TODO: Don't abuse the interface{} return value for both
	// *apidef.EndpointMethodMeta and *time.Time. Probably need to
	// redesign or entirely remove IsRequestValid. See discussion on
	// https://github.com/TykTechnologies/tyk/pull/776
	expired, expTime := a.IsThisAPIVersionExpired(versionMetaData)
	if expired {
		return false, VersionExpired, nil
	}

	// not expired, let's check path info
	requestStatus, meta := a.IsURLAllowedAndIgnored(r, versionPaths, whiteListStatus)

	switch requestStatus {
	case EndPointNotAllowed:
		return false, EndPointNotAllowed, expTime
	case StatusOkAndIgnore:
		return true, StatusOkAndIgnore, expTime
	case StatusRedirectFlowByReply:
		return true, StatusRedirectFlowByReply, meta
	case StatusCached:
		return true, StatusCached, expTime
	case StatusTransform:
		return true, StatusTransform, expTime
	case StatusHeaderInjected:
		return true, StatusHeaderInjected, expTime
	case StatusMethodTransformed:
		return true, StatusMethodTransformed, expTime
	default:
		return true, StatusOk, expTime
	}

}

// Version attempts to extract the version data from a request, depending on where it is stored in the
// request (currently only "header" is supported)
func (a *APISpec) Version(r *http.Request) (*apidef.VersionInfo, []URLSpec, bool, RequestStatus) {
	var version apidef.VersionInfo
	var versionRxPaths []URLSpec
	var versionWLStatus bool

	// try the context first
	versionKey := tykctx.CtxGetVersionKey(r)
	if v := tykctx.CtxGetVersionInfo(r); v != nil {
		version = *v
	} else {
		// Are we versioned?
		if a.VersionData.NotVersioned {
			// Get the first one in the list
			for k, v := range a.VersionData.Versions {
				versionKey = k
				version = v
				break
			}
		} else {
			// Extract Version Info
			versionKey = a.GetVersionFromRequest(r)
			if versionKey == "" {
				return &version, versionRxPaths, versionWLStatus, VersionNotFound
			}
		}

		// Load Version Data - General
		var ok bool
		version, ok = a.VersionData.Versions[versionKey]
		if !ok {
			return &version, versionRxPaths, versionWLStatus, VersionDoesNotExist
		}

		// Lets save this for the future
		tykctx.CtxSetVersionInfo(r, &version)
		tykctx.CtxSetVersionKey(r, versionKey)
	}

	// Load path data and whitelist data for version
	rxPaths, rxOk := a.RxPaths[versionKey]
	whiteListStatus, wlOk := a.WhiteListEnabled[versionKey]

	if !rxOk {
		log.Error("no RX Paths found for version ", versionKey)
		return &version, versionRxPaths, versionWLStatus, VersionDoesNotExist
	}

	if !wlOk {
		log.Error("No whitelist data found")
		return &version, versionRxPaths, versionWLStatus, VersionWhiteListStatusNotFound
	}

	versionRxPaths = rxPaths
	versionWLStatus = whiteListStatus

	return &version, versionRxPaths, versionWLStatus, StatusOk

}

func (s *APISpec) FireEvent(name apidef.TykEvent, meta interface{}) {
	s.FireEventFunc(name, meta, s.EventPaths)
}
