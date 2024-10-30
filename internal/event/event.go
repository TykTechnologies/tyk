package event

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
)

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

	// RateLimitSmoothingUp is the event triggered when rate limit smoothing increases the currently enforced rate limit.
	RateLimitSmoothingUp Event = "RateLimitSmoothingUp"

	// RateLimitSmoothingDown is the event triggered when rate limit smoothing decreases the currently enforced rate limit.
	RateLimitSmoothingDown Event = "RateLimitSmoothingDown"
)

// eventMap contains a map of events to a readable title for the event.
// The title value should not contain ending punctuation.
var eventMap = map[Event]string{
	RateLimitSmoothingUp:   "Rate limit increased with smoothing",
	RateLimitSmoothingDown: "Rate limit decreased with smoothing",
}

// String will return the description for the event if any.
// If no description exists, it will return the event value.
func String(e Event) string {
	v, ok := eventMap[e]
	if ok {
		return v
	}
	return string(e)
}

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

type contextKey string

const eventContextKey contextKey = "events"

// Add adds an event to the request context.
// Add adds an event to the context value in the request.
func Add(r *http.Request, event Event) {
	ctx := r.Context()

	events := Get(ctx)
	events = append(events, event)

	*r = *(r.WithContext(Set(ctx, events)))
}

// Set updates the context with the provided events and returns the new context.
// Set will update the context with a new value and return the new context.
func Set(ctx context.Context, events []Event) context.Context {
	return context.WithValue(ctx, eventContextKey, events)
}

// Get retrieves the events from the context.
// Get will get the events from context. It will return nil if no events in context.
func Get(ctx context.Context) []Event {
	if v, ok := ctx.Value(eventContextKey).([]Event); ok {
		return v
	}
	return nil
}

// EncodeRequestToEvent will write the request out in wire protocol and
// encode it to base64 and store it in an Event object
func EncodeRequestToEvent(r *http.Request) string {
	var asBytes bytes.Buffer
	err := r.Write(&asBytes)
	if err != nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString(asBytes.Bytes())
}
