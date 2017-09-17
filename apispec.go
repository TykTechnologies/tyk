package main

import (
	"github.com/TykTechnologies/tyk/apispec"
)

const (
	LDAPStorageEngine = apispec.LDAPStorageEngine
	RPCStorageEngine  = apispec.RPCStorageEngine
)

// URLStatus is a custom enum type to avoid collisions
type URLStatus = apispec.URLStatus

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
type RequestStatus = apispec.RequestStatus

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

type URLSpec = apispec.URLSpec
type TransformSpec = apispec.TransformSpec
type ExtendedCircuitBreakerMeta = apispec.ExtendedCircuitBreakerMeta
type APISpec = apispec.APISpec