package gateway_test

import (
	"github.com/TykTechnologies/tyk/gateway"
)

// These are symbol shims from the gateway package to make life easier.
// It's all test symbols that have leaked into the package API.
type (
	// Gateway is the service object.
	Gateway             = gateway.Gateway
	ReverseProxy        = gateway.ReverseProxy
	APIDefinitionLoader = gateway.APIDefinitionLoader

	// Middlewares used by tests explicitly
	BaseMiddleware              = gateway.BaseMiddleware
	TransformMiddleware         = gateway.TransformMiddleware
	ResponseTransformMiddleware = gateway.ResponseTransformMiddleware
	ResponseCacheMiddleware     = gateway.ResponseCacheMiddleware
	ResponseGoPluginMiddleware  = gateway.ResponseGoPluginMiddleware
	IPWhiteListMiddleware       = gateway.IPWhiteListMiddleware
	IPBlackListMiddleware       = gateway.IPBlackListMiddleware

	// Tests leakage.
	Test             = gateway.Test
	TestConfig       = gateway.TestConfig
	TestHttpResponse = gateway.TestHttpResponse
	TraceHttpRequest = gateway.TraceHttpRequest

	// Data model.
	APISpec                = gateway.APISpec
	TransformSpec          = gateway.TransformSpec
	HostHealthReport       = gateway.HostHealthReport
	HostCheckCallBacks     = gateway.HostCheckCallBacks
	NotificationCommand    = gateway.NotificationCommand
	Notification           = gateway.Notification
	GraphQLRequest         = gateway.GraphQLRequest
	OASSchemaResponse      = gateway.OASSchemaResponse
	HeaderTransform        = gateway.HeaderTransform
	HeaderTransformOptions = gateway.HeaderTransformOptions
	VersionMetas           = gateway.VersionMetas

	// Interfaces (data model).
	IdExtractor            = gateway.IdExtractor
	WebHookHandler         = gateway.WebHookHandler
	HTTPDashboardHandler   = gateway.HTTPDashboardHandler
	BaseTykResponseHandler = gateway.BaseTykResponseHandler
)

// Constants are a coupling (data model).
const (
	TestHttpAny   = gateway.TestHttpAny
	EH_LogHandler = gateway.EH_LogHandler
	EH_WebHook    = gateway.EH_WebHook

	NoticeGroupReload = gateway.NoticeGroupReload
)

// Global functions are a coupling.
var (
	BuildAPI    = gateway.BuildAPI
	BuildOASAPI = gateway.BuildOASAPI

	StartTest    = gateway.StartTest
	InitTestMain = gateway.InitTestMain

	CreateSession         = gateway.CreateSession
	CreateStandardSession = gateway.CreateStandardSession

	GetTLSClient     = gateway.GetTLSClient
	MockOrgID        = gateway.MockOrgID
	UpdateAPIVersion = gateway.UpdateAPIVersion
	TransformBody    = gateway.TransformBody
	TestReq          = gateway.TestReq
)
