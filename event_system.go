package main

import (
	"fmt"
	"errors"
	"github.com/lonelycode/tykcommon"
)

// The name for event handlers as defined in the API Definition JSON/BSON format
const (
	EH_LogHandler tykcommon.TykEventHandlerName = "eh_log_handler"
)

// Register new event types here, the string is the code used to hook at the Api Deifnititon JSON/BSON level
const (
	EVENT_QuotaExceeded tykcommon.TykEvent = "QuotaExceeded"
	EVENT_RateLimitExceeded tykcommon.TykEvent = "RatelimitExceeded"
	EVENT_AuthFailure tykcommon.TykEvent = "AuthFailure"
	EVENT_KeyExpired tykcommon.TykEvent = "KeyExpired"
	EVENT_VersionFailure tykcommon.TykEvent = "VersionFailure"
)

// EventMetaDefault is a standard embedded struct to be used with custom event metadata types, gives an interface for
// easily extending event metadata objects
type EventMetaDefault struct {
	Message string
}

// EVENT_QuotaExceededMeta is the metadata structure for a quota exceeded event (EVENT_QuotaExceeded)
type EVENT_QuotaExceededMeta struct {
	EventMetaDefault
	Path string
	Origin string
	Key string
}

// EVENT_RateLimitExceededMeta is the metadata structure for a rate limit exceeded event (EVENT_RateLimitExceeded)
type EVENT_RateLimitExceededMeta struct {
	EventMetaDefault
	Path string
	Origin string
	Key string
}

// EVENT_AuthFailureMeta is the metadata structure for an auth failure (EVENT_AuthFailure)
type EVENT_AuthFailureMeta struct {
	EventMetaDefault
	Path string
	Origin string
	Key string
}

// EVENT_KeyExpiredMeta is the metadata structure for an auth failure (EVENT_KeyExpired)
type EVENT_KeyExpiredMeta struct {
	EventMetaDefault
	Path string
	Origin string
	Key string
}

// EVENT_VersionFailureMeta is the metadata structure for an auth failure (EVENT_KeyExpired)
type EVENT_VersionFailureMeta struct {
	EventMetaDefault
	Path string
	Origin string
	Key string
	Reason string
}

// EventMessage is a standard form to send event data to handlers
type EventMessage struct {
	EventType tykcommon.TykEvent
	EventMetaData interface{}
}

// TykEventHandler defines an event handler, e.g. LogMessageEventHandler will handle an event by logging it to stdout.
type TykEventHandler interface {
	New(interface{}) TykEventHandler
	HandleEvent(EventMessage)
}

// GetEventHandlerByName is a convenience function to get event handler instances from an API Definition
func GetEventHandlerByName(handlerConf tykcommon.EventHandlerTriggerConfig) (TykEventHandler, error) {
	switch handlerConf.Handler {
		case EH_LogHandler: return LogMessageEventHandler{}.New(handlerConf.HandlerMeta), nil
		case EH_WebHook: return WebHookHandler{}.New(handlerConf.HandlerMeta), nil
	}

	return nil, errors.New("Handler not found")
}

// FireEvent is added to the tykMiddleware object so it is available across the entire stack
func (t TykMiddleware) FireEvent(eventName tykcommon.TykEvent, eventMetaData interface{}) {

	log.Debug("EVENT FIRED")

	handlers, handlerExists := t.Spec.EventPaths[eventName]

	if handlerExists {
		log.Debug("FOUND EVENT HANDLERS")
		eventMessage := EventMessage{}
		eventMessage.EventMetaData = eventMetaData
		eventMessage.EventType = eventName

		for _, handler := range(handlers) {
			log.Debug("FIRING HANDLER")
			go handler.HandleEvent(eventMessage)
		}
	}
}

// LogMessageEventHandler is a sample Event Handler
type LogMessageEventHandler struct {
	conf map[string]interface{}
}


// New enables the intitialisation of event handler instances when they are created on ApiSpec creation
func (l LogMessageEventHandler) New(handlerConf interface{}) TykEventHandler {
	thisHandler := LogMessageEventHandler{}
	thisHandler.conf = handlerConf.(map[string]interface{})

	return thisHandler
}
// HandleEvent will be fired when the event handler instance is found in an APISpec EventPaths object during a request chain
func (l LogMessageEventHandler) HandleEvent(em EventMessage) {
	var msgConf EVENT_QuotaExceededMeta
	// type assert the metadata and then use it however you like
	msgConf = em.EventMetaData.(EVENT_QuotaExceededMeta)

	var formattedMsgString string
	formattedMsgString = fmt.Sprintf("%s:%s:%s", l.conf["prefix"].(string), em.EventType, msgConf.Message)

	// We can handle specific event types easily
	if em.EventType == EVENT_QuotaExceeded {
		formattedMsgString = fmt.Sprintf("%s:%s:%s:%s", formattedMsgString, msgConf.Key, msgConf.Origin, msgConf.Path)
	}

	log.Warning(formattedMsgString)
}

