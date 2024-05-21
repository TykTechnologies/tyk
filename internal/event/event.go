package event

// Event is the type to bind events.
type Event string

const (
	// QuotaExceeded is the event triggered when quota for a specific key has been exceeded.
	QuotaExceeded Event = "QuotaExceeded"
	// AuthFailure is the event triggered when key has failed authentication or has attempted access and was denied.
	AuthFailure Event = "AuthFailure"
	// KeyExpired is the event triggered when a key has attempted access but is expired.
	KeyExpired Event = "KeyExpired"
	// VersionFailure is the event triggered when a key has attempted access to a version it does not have permission to access.
	VersionFailure Event = "VersionFailure"
	// OrgQuotaExceeded is the event triggered when a quota for a specific organisation has been exceeded.
	OrgQuotaExceeded Event = "OrgQuotaExceeded"
	// OrgRateLimitExceeded is the event triggered when rate limit has been exceeded for a specific organisation.
	OrgRateLimitExceeded Event = "OrgRateLimitExceeded"
	// TriggerExceeded is the event triggered on a configured trigger point.
	TriggerExceeded Event = "TriggerExceeded"
	// BreakerTriggered is the event triggered when either a BreakerTripped, or a BreakerReset event occurs;
	// a status code in the metadata passed to the event handler will indicate which of these events was triggered.
	BreakerTriggered Event = "BreakerTriggered"
	// BreakerTripped is the event triggered when a circuit breaker on a path trips and a service is taken offline.
	BreakerTripped Event = "BreakerTripped"
	// BreakerReset is the event triggered when the circuit breaker comes back on-stream
	BreakerReset Event = "BreakerReset"
	// HostDown is the event triggered when hostchecker finds a host is down/not available.
	HostDown Event = "HostDown"
	// HostUp is the event triggered when hostchecker finds a host is back being available after being offline.
	HostUp Event = "HostUp"
	// TokenCreated is the event triggered when a token is created.
	TokenCreated Event = "TokenCreated"
	// TokenUpdated is the event triggered when a token is updated.
	TokenUpdated Event = "TokenUpdated"
	// TokenDeleted is the event triggered when a token is deleted.
	TokenDeleted Event = "TokenDeleted"
)

// Rate limiter events
const (
	// RateLimitExceeded is the event triggered when rate limit has been exceeded for a specific key.
	RateLimitExceeded Event = "RatelimitExceeded"

	// RateLimitSmoothingUp is the event triggered when rate limit smoothing increases the rate limits.
	RateLimitSmoothingUp Event = "RateLimitSmoothingUp"

	// RateLimitSmoothingDown is the event triggered when rate limit smoothing decreases the rate limits.
	RateLimitSmoothingDown Event = "RateLimitSmoothingDown"
)

// HandlerName to be used as handler codes in API definitions.
type HandlerName string

const (
	// LogHandler is the HandlerName used in classic API definition for log event handler.
	LogHandler HandlerName = "eh_log_handler"
	// WebHookHandler is the HandlerName used in classic API definition for webhook event handler.
	WebHookHandler HandlerName = "eh_web_hook_handler"
	// JSVMHandler is the HandlerName used in classic API definition for javascript event handler.
	JSVMHandler HandlerName = "eh_dynamic_handler"
	// CoProcessHandler is the HandlerName used in classic API definition for coprocess event handler.
	CoProcessHandler HandlerName = "cp_dynamic_handler"
)

// Kind is the action to be performed when an event is triggered, to be used in OAS API definition.
type Kind string

const (
	// WebhookKind is the action to be specified in OAS API definition.
	WebhookKind Kind = "webhook"
)
