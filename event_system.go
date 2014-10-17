package main

import (
	"fmt"
	"errors"
)

/*
Event lifecycle:
1. Trigger occurs
2. Create event object
3. go NotifyEvent(eventObj) as goroutine so inbound request doesn't block
4. NotifyEvent runs through all of the EventHandlers (interface) with the event, these run as a goroutine and quit on their own
5. Event handlers are configurable on a per-api basis in an event_handlers section
6. For each event type, there is a list of handler_code and metadata (e.g. a webhook target URL and a template to use)

On API Def load:
- Init the handlers from the config
- Create the event handler hash map
- Add event handler hash map to the Api Definition

Event starts
- Get event handlers for API
-- Get event handlers for this event
---- Loop through list and fire off handler functions with metadata
 */

type TykEvent string
type TykEventHandlerName string

const (
	EH_LogHandler TykEventHandlerName = "eh_log_handler"
)

const (
	EVENT_QuotaExceeded TykEvent = "QuotaExceeded"
)

type EventMetaDefault struct {
	Message string
	// TODO: Extend this
}

type EVENT_QuotaExceededMeta struct {
	EventMetaDefault
}

type EventMessage struct {
	EventType TykEvent
	EventMetaData interface{}
}

type TykEventHandler interface {
	New(interface{}) TykEventHandler
	HandleEvent(EventMessage)
}


func GetEventHandlerByName(handlerConf EventHandlerTriggerConfig) (TykEventHandler, error) {
	switch handlerConf.Handler {
		case EH_LogHandler: return LogMessageEventHandler{}.New(handlerConf.HandlerMeta), nil
	}

	return nil, errors.New("Handler not found")
}

// FireEvent is added to the tykMiddleware object so it is available across the entire stack
func (t TykMiddleware) FireEvent(eventName TykEvent, eventMetaData interface{}) {

	log.Debu("EVENT FIRED")

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

// Sample Event Handler
type LogMessageEventHandler struct {
	conf map[string]interface{}
}

func (l LogMessageEventHandler) New(handlerConf interface{}) TykEventHandler {
	thisHandler := LogMessageEventHandler{}
	log.Error(handlerConf)
	thisHandler.conf = handlerConf.(map[string]interface{})

	return thisHandler
}

func (l LogMessageEventHandler) HandleEvent(em EventMessage) {
	var msgConf EVENT_QuotaExceededMeta
	msgConf = em.EventMetaData.(EVENT_QuotaExceededMeta)

	var formattedMsgString string
	formattedMsgString = fmt.Sprintf("%s:\t %s", l.conf["prefix"].(string), msgConf.Message)

	log.Warning(formattedMsgString)
}

