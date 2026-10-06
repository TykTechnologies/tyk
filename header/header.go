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
	SetCookie               = "Set-Cookie"
	Cookie                  = "Cookie"
	TransferEncoding        = "Transfer-Encoding"
	Host                    = "Host"
)

const (
	TykHookshot               = "Tyk-Hookshot"
	ApplicationJSON           = "application/json"
	ApplicationXML            = "application/xml"
	ApplicationSoapXML        = "application/soap+xml"
	ApplicationFormURLEncoded = "application/x-www-form-urlencoded"
	TextXML                   = "text/xml"
)

const (
	XRealIP               = "X-Real-IP"
	XForwardFor           = "X-Forwarded-For"
	XAuthResult           = "X-Auth-Result"
	XSessionAlias         = "X-Session-Alias"
	XInitialURI           = "X-Initial-URI"
	XForwardProto         = "X-Forwarded-Proto"
	XContentTypeOptions   = "X-Content-Type-Options"
	XXSSProtection        = "X-XSS-Protection"
	XFrameOptions         = "X-Frame-Options"
	XTykNodeID            = "x-tyk-nodeid"
	XTykSessionID         = "x-tyk-session-id"
	XTykNonce             = "x-tyk-nonce"
	XTykHostname          = "x-tyk-hostname"
	XGenerator            = "X-Generator"
	XTykAuthorization     = "X-Tyk-Authorization"
	XTykAcceptExampleName = "X-Tyk-Accept-Example-Name"
	XTykAcceptExampleCode = "X-Tyk-Accept-Example-Code"
)

// Node metadata the gateway sends to the Dashboard on every register
// (/register/node) and heartbeat (/register/ping) request. Names mirror the
// MDCB NodeData JSON fields. The counts can be 0 on the initial register (the
// first reload runs after registration); the heartbeat is their source of truth.
const (
	XTykNodeVersion   = "x-tyk-node-version"
	XTykNodeSegmented = "x-tyk-node-segmented"
	XTykNodeTags      = "x-tyk-node-tags" // comma-separated, omitted when empty
	XTykAPIsCount     = "x-tyk-apis-count"
	XTykPoliciesCount = "x-tyk-policies-count"
	XTykNodePID       = "x-tyk-node-pid"
	XTykNodeAddress   = "x-tyk-node-address"
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
	// XRateLimitLimit The maximum number of requests that the client is allowed to make in a given time period
	XRateLimitLimit = "X-RateLimit-Limit"

	// XRateLimitRemaining The number of requests remaining in the current rate limit window.
	XRateLimitRemaining = "X-RateLimit-Remaining"

	// XRateLimitReset The number of seconds until the rate limit resets.
	XRateLimitReset = "X-RateLimit-Reset"
)
