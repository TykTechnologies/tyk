package graphengine

type ComplexityFailReason int

const (
	ComplexityFailReasonNone ComplexityFailReason = iota
	ComplexityFailReasonInternalError
	ComplexityFailReasonDepthLimitExceeded
)

type GranularAccessFailReason int

const (
	GranularAccessFailReasonNone GranularAccessFailReason = iota
	GranularAccessFailReasonInternalError
	GranularAccessFailReasonValidationError
	GranularAccessFailReasonIntrospectionDisabled
)

type ReverseProxyType int

const (
	ReverseProxyTypeNone ReverseProxyType = iota
	ReverseProxyTypeIntrospection
	ReverseProxyTypeWebsocketUpgrade
	ReverseProxyTypeGraphEngine
	ReverseProxyTypePreFlight
)
