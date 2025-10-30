package gateway

import (
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/internal/event"
)

const (
	EventBreakerTriggered  = event.BreakerTriggered
	EventRateLimitExceeded = event.RateLimitExceeded
	EventWebHookHandler    = event.WebHookHandler
	TestHttpAny            = gateway.TestHttpAny
)

type (
	Test                    = gateway.Test
	TestConfig              = gateway.TestConfig
	OASSchemaResponse       = gateway.OASSchemaResponse
	APIAllCertificateBasics = gateway.APIAllCertificateBasics
)

var (
	LoopingUrl            = gateway.LoopingUrl
	StartTest             = gateway.StartTest
	InitTestMain          = gateway.InitTestMain
	CreateStandardSession = gateway.CreateStandardSession
	APILoopingName        = gateway.APILoopingName
	EnableTestDNSMock     = gateway.EnableTestDNSMock
)
