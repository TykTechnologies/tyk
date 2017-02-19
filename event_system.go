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
)

// The name for event handlers as defined in the API Definition JSON/BSON format
const (
	EH_LogHandler apidef.TykEventHandlerName = "eh_log_handler"
)

// Register new event types here, the string is the code used to hook at the Api Deifnititon JSON/BSON level
const (
	EVENT_QuotaExceeded     apidef.TykEvent = "QuotaExceeded"
	EVENT_RateLimitExceeded apidef.TykEvent = "RatelimitExceeded"
	EVENT_AuthFailure       apidef.TykEvent = "AuthFailure"
	EVENT_KeyExpired        apidef.TykEvent = "KeyExpired"
	EVENT_VersionFailure    apidef.TykEvent = "VersionFailure"
	EVENT_OrgQuotaExceeded  apidef.TykEvent = "OrgQuotaExceeded"
	EVENT_TriggerExceeded   apidef.TykEvent = "TriggerExceeded"
	EVENT_BreakerTriggered  apidef.TykEvent = "BreakerTriggered"
	EVENT_HOSTDOWN          apidef.TykEvent = "HostDown"
	EVENT_HOSTUP            apidef.TykEvent = "HostUp"
	EVENT_TokenCreated      apidef.TykEvent = "TokenCreated"
	EVENT_TokenUpdated      apidef.TykEvent = "TokenUpdated"
	EVENT_TokenDeleted      apidef.TykEvent = "TokenDeleted"
)

// EventMetaDefault is a standard embedded struct to be used with custom event metadata types, gives an interface for
// easily extending event metadata objects
type EventMetaDefault struct {
	Message            string
	OriginatingRequest string
}

type EVENT_HostStatusMeta struct {
	EventMetaDefault
	HostInfo HostHealthReport
}

// EVENT_QuotaExceededMeta is the metadata structure for a quota exceeded event (EVENT_QuotaExceeded)
type EVENT_QuotaExceededMeta struct {
	EventMetaDefault
	Path   string
	Origin string
	Key    string
}

// EVENT_RateLimitExceededMeta is the metadata structure for a rate limit exceeded event (EVENT_RateLimitExceeded)
type EVENT_RateLimitExceededMeta struct {
	EventMetaDefault
	Path   string
	Origin string
	Key    string
}

// EVENT_AuthFailureMeta is the metadata structure for an auth failure (EVENT_AuthFailure)
type EVENT_AuthFailureMeta struct {
	EventMetaDefault
	Path   string
	Origin string
	Key    string
}

// EVENT_CurcuitBreakerMeta is the event status for a circuit breaker tripping
type EVENT_CurcuitBreakerMeta struct {
	EventMetaDefault
	Path         string
	APIID        string
	CircuitEvent circuit.BreakerEvent
}

// EVENT_KeyExpiredMeta is the metadata structure for an auth failure (EVENT_KeyExpired)
type EVENT_KeyExpiredMeta struct {
	EventMetaDefault
	Path   string
	Origin string
	Key    string
}

// EVENT_VersionFailureMeta is the metadata structure for an auth failure (EVENT_KeyExpired)
type EVENT_VersionFailureMeta struct {
	EventMetaDefault
	Path   string
	Origin string
	Key    string
	Reason string
}

// EVENT_VersionFailureMeta is the metadata structure for an auth failure (EVENT_KeyExpired)
type EVENT_TriggerExceededMeta struct {
	EventMetaDefault
	Org          string
	Key          string
	TriggerLimit int64
}

// EVENT_VersionFailureMeta is the metadata structure for an auth failure (EVENT_KeyExpired)
type EVENT_TokenMeta struct {
	EventMetaDefault
	Org string
	Key string
}

// EventMessage is a standard form to send event data to handlers
type EventMessage struct {
	EventType     apidef.TykEvent
	EventMetaData interface{}
	TimeStamp     string
}

// TykEventHandler defines an event handler, e.g. LogMessageEventHandler will handle an event by logging it to stdout.
type TykEventHandler interface {
	New(interface{}) (TykEventHandler, error)
	HandleEvent(EventMessage)
}

// EncodeRequestToEvent will write the request out in wire protocol and
// encode it to base64 and store it in an Event object
func EncodeRequestToEvent(r *http.Request) string {
	var asBytes bytes.Buffer
	r.Write(&asBytes)

	return base64.StdEncoding.EncodeToString(asBytes.Bytes())
}

// GetEventHandlerByName is a convenience function to get event handler instances from an API Definition
func GetEventHandlerByName(handlerConf apidef.EventHandlerTriggerConfig, Spec *APISpec) (TykEventHandler, error) {

	var conf interface{}
	switch handlerConf.HandlerMeta.(type) {
	case bson.M:
		asByte, ok := json.Marshal(handlerConf.HandlerMeta)
		if ok != nil {
			log.Error("Failed to unmarshal handler meta! ", ok)
		}
		if err := json.Unmarshal(asByte, &conf); err != nil {
			log.Error("Return conversion failed, ", err)
		}
	default:
		conf = handlerConf.HandlerMeta
	}

	switch handlerConf.Handler {
	case EH_LogHandler:
		return (&LogMessageEventHandler{}).New(conf)
	case EH_WebHook:
		return (&WebHookHandler{}).New(conf)
	case EH_JSVMHandler:
		// Load the globals and file here
		if Spec != nil {
			jsVmEventHandler, err := (&JSVMEventHandler{Spec: Spec}).New(conf)
			if err == nil {
				GlobalEventsJSVM.LoadJSPaths([]string{conf.(map[string]interface{})["path"].(string)}, "")
			}
			return jsVmEventHandler, err
		}
	case EH_CoProcessHandler:
		if Spec != nil {
			var coprocessEventHandler TykEventHandler
			var err error
			if GlobalDispatcher == nil {
				err = errors.New("no CP available")
			} else {
				coprocessEventHandler, err = CoProcessEventHandler{Spec: Spec}.New(conf)
			}
			return coprocessEventHandler, err
		}

	}

	return nil, errors.New("Handler not found")
}

// FireEvent is added to the tykMiddleware object so it is available across the entire stack
func (t *TykMiddleware) FireEvent(name apidef.TykEvent, meta interface{}) {
	fireEvent(name, meta, t.Spec.EventPaths)
}

func fireEvent(name apidef.TykEvent, meta interface{}, handlers map[apidef.TykEvent][]TykEventHandler) {
	log.Debug("EVENT FIRED: ", name)
	if handlers, e := handlers[name]; e {
		log.Debug("FOUND EVENT HANDLERS")
		eventMessage := EventMessage{
			EventMetaData: meta,
			EventType:     name,
			TimeStamp:     time.Now().Local().String(),
		}
		for _, handler := range handlers {
			log.Debug("FIRING HANDLER")
			go handler.HandleEvent(eventMessage)
		}
	}
}

func (s *APISpec) FireEvent(name apidef.TykEvent, meta interface{}) {
	fireEvent(name, meta, s.EventPaths)
}

// LogMessageEventHandler is a sample Event Handler
type LogMessageEventHandler struct {
	conf map[string]interface{}
}

// New enables the intitialisation of event handler instances when they are created on ApiSpec creation
func (l *LogMessageEventHandler) New(handlerConf interface{}) (TykEventHandler, error) {
	handler := &LogMessageEventHandler{}
	handler.conf = handlerConf.(map[string]interface{})
	return handler, nil
}

// HandleEvent will be fired when the event handler instance is found in an APISpec EventPaths object during a request chain
func (l *LogMessageEventHandler) HandleEvent(em EventMessage) {
	formattedMsgString := fmt.Sprintf("%s:%s", l.conf["prefix"].(string), em.EventType)

	// We can handle specific event types easily
	if em.EventType == EVENT_QuotaExceeded {
		msgConf := em.EventMetaData.(EVENT_QuotaExceededMeta)
		formattedMsgString = fmt.Sprintf("%s:%s:%s:%s", formattedMsgString, msgConf.Key, msgConf.Origin, msgConf.Path)
	}

	if em.EventType == EVENT_BreakerTriggered {
		msgConf := em.EventMetaData.(EVENT_CurcuitBreakerMeta)
		formattedMsgString = fmt.Sprintf("%s:%s:%s: [STATUS] %v", formattedMsgString, msgConf.APIID, msgConf.Path, msgConf.CircuitEvent)
	}

	log.Warning(formattedMsgString)
}

func InitGenericEventHandlers(theseEvents apidef.EventHandlerMetaConfig) map[apidef.TykEvent][]TykEventHandler {
	actualEventHandlers := make(map[apidef.TykEvent][]TykEventHandler)
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

func FireSystemEvent(name apidef.TykEvent, meta interface{}) {
	fireEvent(name, meta, config.EventTriggers)
}
