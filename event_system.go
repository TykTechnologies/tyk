package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/rubyist/circuitbreaker"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

// The name for event handlers as defined in the API Definition JSON/BSON format
const EH_LogHandler apidef.TykEventHandlerName = "eh_log_handler"

// Register new event types here, the string is the code used to hook at the Api Deifnititon JSON/BSON level
const (
	EventQuotaExceeded        apidef.TykEvent = "QuotaExceeded"
	EventRateLimitExceeded    apidef.TykEvent = "RatelimitExceeded"
	EventAuthFailure          apidef.TykEvent = "AuthFailure"
	EventKeyExpired           apidef.TykEvent = "KeyExpired"
	EventVersionFailure       apidef.TykEvent = "VersionFailure"
	EventOrgQuotaExceeded     apidef.TykEvent = "OrgQuotaExceeded"
	EventOrgRateLimitExceeded apidef.TykEvent = "OrgRateLimitExceeded"
	EventTriggerExceeded      apidef.TykEvent = "TriggerExceeded"
	EventBreakerTriggered     apidef.TykEvent = "BreakerTriggered"
	EventHOSTDOWN             apidef.TykEvent = "HostDown"
	EventHOSTUP               apidef.TykEvent = "HostUp"
	EventTokenCreated         apidef.TykEvent = "TokenCreated"
	EventTokenUpdated         apidef.TykEvent = "TokenUpdated"
	EventTokenDeleted         apidef.TykEvent = "TokenDeleted"
)

// EventMetaDefault is a standard embedded struct to be used with custom event metadata types, gives an interface for
// easily extending event metadata objects
type EventMetaDefault struct {
	Message            string
	OriginatingRequest string
}

type EventHostStatusMeta struct {
	EventMetaDefault
	HostInfo HostHealthReport
}

// EventKeyFailureMeta is the metadata structure for any failure related
// to a key, such as quota or auth failures.
type EventKeyFailureMeta struct {
	EventMetaDefault
	Path   string
	Origin string
	Key    string
}

// EventCurcuitBreakerMeta is the event status for a circuit breaker tripping
type EventCurcuitBreakerMeta struct {
	EventMetaDefault
	Path         string
	APIID        string
	CircuitEvent circuit.BreakerEvent
}

// EventVersionFailureMeta is the metadata structure for an auth failure (EventKeyExpired)
type EventVersionFailureMeta struct {
	EventMetaDefault
	Path   string
	Origin string
	Key    string
	Reason string
}

type EventTriggerExceededMeta struct {
	EventMetaDefault
	Org          string
	Key          string
	TriggerLimit int64
}

type EventTokenMeta struct {
	EventMetaDefault
	Org string
	Key string
}

// EncodeRequestToEvent will write the request out in wire protocol and
// encode it to base64 and store it in an Event object
func EncodeRequestToEvent(r *http.Request) string {
	var asBytes bytes.Buffer
	r.Write(&asBytes)

	return base64.StdEncoding.EncodeToString(asBytes.Bytes())
}

// EventHandlerByName is a convenience function to get event handler instances from an API Definition
func EventHandlerByName(handlerConf apidef.EventHandlerTriggerConfig, spec *APISpec) (config.TykEventHandler, error) {

	conf := handlerConf.HandlerMeta
	switch handlerConf.Handler {
	case EH_LogHandler:
		h := &LogMessageEventHandler{}
		err := h.Init(conf)
		return h, err
	case EH_WebHook:
		h := &WebHookHandler{}
		err := h.Init(conf)
		return h, err
	case EH_JSVMHandler:
		// Load the globals and file here
		if spec != nil {
			h := &JSVMEventHandler{Spec: spec}
			err := h.Init(conf)
			if err == nil {
				GlobalEventsJSVM.LoadJSPaths([]string{conf["path"].(string)}, "")
			}
			return h, err
		}
	case EH_CoProcessHandler:
		if spec != nil {
			if GlobalDispatcher == nil {
				return nil, errors.New("no CP available")
			}
			h := &CoProcessEventHandler{}
			h.Spec = spec
			err := h.Init(conf)
			return h, err
		}
	}

	return nil, errors.New("Handler not found")
}

func fireEvent(name apidef.TykEvent, meta interface{}, handlers map[apidef.TykEvent][]config.TykEventHandler) {
	if handlers, e := handlers[name]; e {
		eventMessage := config.EventMessage{
			Meta:      meta,
			Type:      name,
			TimeStamp: time.Now().Local().String(),
		}
		for _, handler := range handlers {
			go handler.HandleEvent(eventMessage)
		}
	}
}

func (s *APISpec) FireEvent(name apidef.TykEvent, meta interface{}) {
	fireEvent(name, meta, s.EventPaths)
}

func FireSystemEvent(name apidef.TykEvent, meta interface{}) {
	fireEvent(name, meta, config.Global.EventTriggers)
}

// LogMessageEventHandler is a sample Event Handler
type LogMessageEventHandler struct {
	prefix string
}

// New enables the intitialisation of event handler instances when they are created on ApiSpec creation
func (l *LogMessageEventHandler) Init(handlerConf interface{}) error {
	l.prefix = handlerConf.(map[string]interface{})["prefix"].(string)
	return nil
}

// HandleEvent will be fired when the event handler instance is found in an APISpec EventPaths object during a request chain
func (l *LogMessageEventHandler) HandleEvent(em config.EventMessage) {
	logMsg := fmt.Sprintf("%s:%s", l.prefix, em.Type)

	// We can handle specific event types easily
	if em.Type == EventQuotaExceeded {
		msgConf := em.Meta.(EventKeyFailureMeta)
		logMsg = fmt.Sprintf("%s:%s:%s:%s", logMsg, msgConf.Key, msgConf.Origin, msgConf.Path)
	}

	if em.Type == EventBreakerTriggered {
		msgConf := em.Meta.(EventCurcuitBreakerMeta)
		logMsg = fmt.Sprintf("%s:%s:%s: [STATUS] %v", logMsg, msgConf.APIID, msgConf.Path, msgConf.CircuitEvent)
	}

	log.Warning(logMsg)
}

func InitGenericEventHandlers(theseEvents apidef.EventHandlerMetaConfig) map[apidef.TykEvent][]config.TykEventHandler {
	actualEventHandlers := make(map[apidef.TykEvent][]config.TykEventHandler)
	for eventName, eventHandlerConfs := range theseEvents.Events {
		log.Debug("FOUND EVENTS TO INIT")
		for _, handlerConf := range eventHandlerConfs {
			log.Debug("CREATING EVENT HANDLERS")
			eventHandlerInstance, err := EventHandlerByName(handlerConf, nil)

			if err != nil {
				log.Error("Failed to init event handler: ", err)
			} else {
				log.Debug("Init Event Handler: ", eventName)
				actualEventHandlers[eventName] = append(actualEventHandlers[eventName], eventHandlerInstance)
			}

		}
	}
	return actualEventHandlers
}
