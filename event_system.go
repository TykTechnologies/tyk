package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/rubyist/circuitbreaker"
	"gopkg.in/mgo.v2/bson"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

// The name for event handlers as defined in the API Definition JSON/BSON format
const EH_LogHandler apidef.TykEventHandlerName = "eh_log_handler"

// Register new event types here, the string is the code used to hook at the Api Deifnititon JSON/BSON level
const (
	EventQuotaExceeded     apidef.TykEvent = "QuotaExceeded"
	EventRateLimitExceeded apidef.TykEvent = "RatelimitExceeded"
	EventAuthFailure       apidef.TykEvent = "AuthFailure"
	EventKeyExpired        apidef.TykEvent = "KeyExpired"
	EventVersionFailure    apidef.TykEvent = "VersionFailure"
	EventOrgQuotaExceeded  apidef.TykEvent = "OrgQuotaExceeded"
	EventTriggerExceeded   apidef.TykEvent = "TriggerExceeded"
	EventBreakerTriggered  apidef.TykEvent = "BreakerTriggered"
	EventHOSTDOWN          apidef.TykEvent = "HostDown"
	EventHOSTUP            apidef.TykEvent = "HostUp"
	EventTokenCreated      apidef.TykEvent = "TokenCreated"
	EventTokenUpdated      apidef.TykEvent = "TokenUpdated"
	EventTokenDeleted      apidef.TykEvent = "TokenDeleted"
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

// EventQuotaExceededMeta is the metadata structure for a quota exceeded event (EventQuotaExceeded)
type EventQuotaExceededMeta struct {
	EventMetaDefault
	Path   string
	Origin string
	Key    string
}

// EventRateLimitExceededMeta is the metadata structure for a rate limit exceeded event (EventRateLimitExceeded)
type EventRateLimitExceededMeta struct {
	EventMetaDefault
	Path   string
	Origin string
	Key    string
}

// EventAuthFailureMeta is the metadata structure for an auth failure (EventAuthFailure)
type EventAuthFailureMeta struct {
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

// EventKeyExpiredMeta is the metadata structure for an auth failure (EventKeyExpired)
type EventKeyExpiredMeta struct {
	EventMetaDefault
	Path   string
	Origin string
	Key    string
}

// EventVersionFailureMeta is the metadata structure for an auth failure (EventKeyExpired)
type EventVersionFailureMeta struct {
	EventMetaDefault
	Path   string
	Origin string
	Key    string
	Reason string
}

// EventVersionFailureMeta is the metadata structure for an auth failure (EventKeyExpired)
type EventTriggerExceededMeta struct {
	EventMetaDefault
	Org          string
	Key          string
	TriggerLimit int64
}

// EventVersionFailureMeta is the metadata structure for an auth failure (EventKeyExpired)
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

// GetEventHandlerByName is a convenience function to get event handler instances from an API Definition
func GetEventHandlerByName(handlerConf apidef.EventHandlerTriggerConfig, spec *APISpec) (config.TykEventHandler, error) {

	var conf interface{}
	switch x := handlerConf.HandlerMeta.(type) {
	case bson.M:
		asByte, ok := json.Marshal(x)
		if ok != nil {
			log.Error("Failed to unmarshal handler meta! ", ok)
		}
		if err := json.Unmarshal(asByte, &conf); err != nil {
			log.Error("Return conversion failed, ", err)
		}
	default:
		conf = x
	}

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
				GlobalEventsJSVM.LoadJSPaths([]string{conf.(map[string]interface{})["path"].(string)}, "")
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

// FireEvent is added to the tykMiddleware object so it is available across the entire stack
func (t *TykMiddleware) FireEvent(name apidef.TykEvent, meta interface{}) {
	fireEvent(name, meta, t.Spec.EventPaths)
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
	fireEvent(name, meta, globalConf.EventTriggers)
}

// LogMessageEventHandler is a sample Event Handler
type LogMessageEventHandler struct {
	conf map[string]interface{}
}

// New enables the intitialisation of event handler instances when they are created on ApiSpec creation
func (l *LogMessageEventHandler) Init(handlerConf interface{}) error {
	l.conf = handlerConf.(map[string]interface{})
	return nil
}

// HandleEvent will be fired when the event handler instance is found in an APISpec EventPaths object during a request chain
func (l *LogMessageEventHandler) HandleEvent(em config.EventMessage) {
	formattedMsgString := fmt.Sprintf("%s:%s", l.conf["prefix"].(string), em.Type)

	// We can handle specific event types easily
	if em.Type == EventQuotaExceeded {
		msgConf := em.Meta.(EventQuotaExceededMeta)
		formattedMsgString = fmt.Sprintf("%s:%s:%s:%s", formattedMsgString, msgConf.Key, msgConf.Origin, msgConf.Path)
	}

	if em.Type == EventBreakerTriggered {
		msgConf := em.Meta.(EventCurcuitBreakerMeta)
		formattedMsgString = fmt.Sprintf("%s:%s:%s: [STATUS] %v", formattedMsgString, msgConf.APIID, msgConf.Path, msgConf.CircuitEvent)
	}

	log.Warning(formattedMsgString)
}

func InitGenericEventHandlers(theseEvents apidef.EventHandlerMetaConfig) map[apidef.TykEvent][]config.TykEventHandler {
	actualEventHandlers := make(map[apidef.TykEvent][]config.TykEventHandler)
	for eventName, eventHandlerConfs := range theseEvents.Events {
		log.Debug("FOUND EVENTS TO INIT")
		for _, handlerConf := range eventHandlerConfs {
			log.Debug("CREATING EVENT HANDLERS")
			eventHandlerInstance, err := GetEventHandlerByName(handlerConf, nil)

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
