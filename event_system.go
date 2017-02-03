package main

import (
	"bytes"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/TykTechnologies/tykcommon"
	"github.com/rubyist/circuitbreaker"
	"gopkg.in/mgo.v2/bson"
)

// The name for event handlers as defined in the API Definition JSON/BSON format
const (
	EH_LogHandler tykcommon.TykEventHandlerName = "eh_log_handler"
)

// Register new event types here, the string is the code used to hook at the Api Deifnititon JSON/BSON level
const (
	EVENT_QuotaExceeded     tykcommon.TykEvent = "QuotaExceeded"
	EVENT_RateLimitExceeded tykcommon.TykEvent = "RatelimitExceeded"
	EVENT_AuthFailure       tykcommon.TykEvent = "AuthFailure"
	EVENT_KeyExpired        tykcommon.TykEvent = "KeyExpired"
	EVENT_VersionFailure    tykcommon.TykEvent = "VersionFailure"
	EVENT_OrgQuotaExceeded  tykcommon.TykEvent = "OrgQuotaExceeded"
	EVENT_TriggerExceeded   tykcommon.TykEvent = "TriggerExceeded"
	EVENT_BreakerTriggered  tykcommon.TykEvent = "BreakerTriggered"
	EVENT_HOSTDOWN          tykcommon.TykEvent = "HostDown"
	EVENT_HOSTUP            tykcommon.TykEvent = "HostUp"
	EVENT_TokenCreated      tykcommon.TykEvent = "TokenCreated"
	EVENT_TokenUpdated      tykcommon.TykEvent = "TokenUpdated"
	EVENT_TokenDeleted      tykcommon.TykEvent = "TokenDeleted"
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
	EventType     tykcommon.TykEvent
	EventMetaData interface{}
	TimeStamp     string
}

// TykEventHandler defines an event handler, e.g. LogMessageEventHandler will handle an event by logging it to stdout.
type TykEventHandler interface {
	New(interface{}) (TykEventHandler, error)
	HandleEvent(EventMessage)
}

// EncodeRequestToEvent will write the request out in wire protocol and encode it to b64 and store it in an Event object
func EncodeRequestToEvent(r *http.Request) string {
	var asBytes bytes.Buffer
	r.Write(&asBytes)

	uEnc := b64.StdEncoding.EncodeToString(asBytes.Bytes())
	return uEnc
}

// GetEventHandlerByName is a convenience function to get event handler instances from an API Definition
func GetEventHandlerByName(handlerConf tykcommon.EventHandlerTriggerConfig, Spec *APISpec) (TykEventHandler, error) {

	var conf interface{}
	switch handlerConf.HandlerMeta.(type) {
	case bson.M:
		asByte, ok := json.Marshal(handlerConf.HandlerMeta)
		if ok != nil {
			log.Error("Failed to unmarshal handler meta! ", ok)
		}
		mErr := json.Unmarshal(asByte, &conf)
		if mErr != nil {
			log.Error("Return conversion failed, ", mErr)
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
func (t *TykMiddleware) FireEvent(eventName tykcommon.TykEvent, eventMetaData interface{}) {

	log.Debug("EVENT FIRED")
	handlers, handlerExists := t.Spec.EventPaths[eventName]

	if handlerExists {
		log.Debug("FOUND EVENT HANDLERS")
		eventMessage := EventMessage{}
		eventMessage.EventMetaData = eventMetaData
		eventMessage.EventType = eventName
		eventMessage.TimeStamp = time.Now().Local().String()

		for _, handler := range handlers {
			log.Debug("FIRING HANDLER")
			go handler.HandleEvent(eventMessage)
		}
	}
}

func (s *APISpec) FireEvent(eventName tykcommon.TykEvent, eventMetaData interface{}) {

	log.Debug("EVENT FIRED: ", eventName)
	handlers, handlerExists := s.EventPaths[eventName]

	if handlerExists {
		log.Debug("FOUND EVENT HANDLERS")
		eventMessage := EventMessage{}
		eventMessage.EventMetaData = eventMetaData
		eventMessage.EventType = eventName
		eventMessage.TimeStamp = time.Now().Local().String()

		for _, handler := range handlers {
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

func InitGenericEventHandlers(theseEvents tykcommon.EventHandlerMetaConfig) map[tykcommon.TykEvent][]TykEventHandler {
	actualEventHandlers := make(map[tykcommon.TykEvent][]TykEventHandler)
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

func FireSystemEvent(eventName tykcommon.TykEvent, eventMetaData interface{}) {

	log.Debug("EVENT FIRED: ", eventName)
	handlers, handlerExists := config.EventTriggers[eventName]

	if handlerExists {
		log.Debug("FOUND EVENT HANDLERS")
		eventMessage := EventMessage{}
		eventMessage.EventMetaData = eventMetaData
		eventMessage.EventType = eventName
		eventMessage.TimeStamp = time.Now().Local().String()

		for _, handler := range handlers {
			log.Debug("FIRING HANDLER")
			go handler.HandleEvent(eventMessage)
		}
	}
}
