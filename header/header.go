package header

const (
	UserAgent               = "User-Agent"
	ContentType             = "Content-Type"
	ContentLength           = "Content-Length"
	Authorization           = "Authorization"
	ContentEncoding         = "Content-Encoding"
	Accept                  = "Accept"
	AcceptEncoding          = "Accept-Encoding"
	StrictTransportSecurity = "Strict-Transport-Security"
	CacheControl            = "Cache-Control"
	Pragma                  = "Pragma"
	Expires                 = "Expires"
	Connection              = "Connection"
	WWWAuthenticate         = "WWW-Authenticate"
)

const (
	TykHookshot     = "Tyk-Hookshot"
	ApplicationJSON = "application/json"
	ApplicationXML  = "application/xml"
	TextXML         = "text/xml"
)

const (
	XRealIP             = "X-Real-IP"
	XForwardFor         = "X-Forwarded-For"
	XAuthResult         = "X-Auth-Result"
	XSessionAlias       = "X-Session-Alias"
	XInitialURI         = "X-Initial-URI"
	XForwardProto       = "X-Forwarded-Proto"
	XContentTypeOptions = "X-Content-Type-Options"
	XXSSProtection      = "X-XSS-Protection"
	XFrameOptions       = "X-Frame-Options"
	XTykNodeID          = "x-tyk-nodeid"
	XTykSessionID       = "x-tyk-session-id"
	XTykNonce           = "x-tyk-nonce"
	XTykHostname        = "x-tyk-hostname"
	XGenerator          = "X-Generator"
	XTykAuthorization   = "X-Tyk-Authorization"
)

// upgrade and websocket
const (
	Upgrade              = "Upgrade"
	SecWebSocketProtocol = "Sec-WebSocket-Protocol"
	SecWebSocketVersion  = "Sec-WebSocket-Version"
	SecWebSocketKey      = "Sec-WebSocket-Key"
)

// Gateway's custom response headers
const (
	XRateLimitLimit     = "X-RateLimit-Limit"
	XRateLimitRemaining = "X-RateLimit-Remaining"
	XRateLimitReset     = "X-RateLimit-Reset"
)
