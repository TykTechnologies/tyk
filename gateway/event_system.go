package gateway

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	circuit "github.com/TykTechnologies/circuitbreaker"
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
	EventBreakerTripped       apidef.TykEvent = "BreakerTripped"
	EventBreakerReset         apidef.TykEvent = "BreakerReset"
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
	OrgID           string `json:"org_id"`
	Key             string `json:"key"`
	TriggerLimit    int64  `json:"trigger_limit"`
	UsagePercentage int64  `json:"usage_percentage"`
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
func (gw *Gateway) EventHandlerByName(handlerConf apidef.EventHandlerTriggerConfig, spec *APISpec) (config.TykEventHandler, error) {

	conf := handlerConf.HandlerMeta
	switch handlerConf.Handler {
	case EH_LogHandler:
		h := &LogMessageEventHandler{Gw: gw}
		err := h.Init(conf)
		return h, err
	case EH_WebHook:
		h := &WebHookHandler{Gw: gw}
		err := h.Init(conf)
		return h, err
	case EH_JSVMHandler:
		// Load the globals and file here
		if spec != nil {
			h := &JSVMEventHandler{Spec: spec, Gw: gw}
			err := h.Init(conf)
			if err == nil {
				gw.GlobalEventsJSVM.LoadJSPaths([]string{conf["path"].(string)}, "")
			}
			return h, err
		}
	case EH_CoProcessHandler:
		if spec != nil {
			dispatcher := loadedDrivers[spec.CustomMiddleware.Driver]
			if dispatcher == nil {
				return nil, errors.New("no plugin driver is available")
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
	log.Debug("EVENT FIRED: ", name)
	if handlers, e := handlers[name]; e {
		log.Debugf("FOUND %d EVENT HANDLERS", len(handlers))
		eventMessage := config.EventMessage{
			Meta:      meta,
			Type:      name,
			TimeStamp: time.Now().Local().String(),
		}
		for _, handler := range handlers {
			log.Debug("FIRING HANDLER: ", handler)
			go handler.HandleEvent(eventMessage)
		}
	}
}

func (s *APISpec) FireEvent(name apidef.TykEvent, meta interface{}) {
	fireEvent(name, meta, s.EventPaths)
}

func (gw *Gateway) FireSystemEvent(name apidef.TykEvent, meta interface{}) {
	fireEvent(name, meta, gw.GetConfig().GetEventTriggers())
}

// LogMessageEventHandler is a sample Event Handler
type LogMessageEventHandler struct {
	prefix string
	logger *logrus.Logger
	Gw     *Gateway `json:"-"`
}

// New enables the intitialisation of event handler instances when they are created on ApiSpec creation
func (l *LogMessageEventHandler) Init(handlerConf interface{}) error {
	conf := handlerConf.(map[string]interface{})
	l.prefix = conf["prefix"].(string)
	l.logger = log
	if l.Gw.isRunningTests() {
		logger, ok := conf["logger"]
		if ok {
			l.logger = logger.(*logrus.Logger)
		}
	}
	return nil
}

// HandleEvent will be fired when the event handler instance is found in an APISpec EventPaths object during a request chain
func (l *LogMessageEventHandler) HandleEvent(em config.EventMessage) {
	logMsg := l.prefix + ":" + string(em.Type)

	// We can handle specific event types easily
	if em.Type == EventQuotaExceeded {
		msgConf := em.Meta.(EventKeyFailureMeta)
		logMsg = logMsg + ":" + msgConf.Key + ":" + msgConf.Origin + ":" + msgConf.Path
	}

	if em.Type == EventBreakerTriggered {
		msgConf := em.Meta.(EventCurcuitBreakerMeta)
		logMsg = logMsg + ":" + msgConf.APIID + ":" + msgConf.Path + ": [STATUS] " + fmt.Sprint(msgConf.CircuitEvent)
	}

	l.logger.Warning(logMsg)
}

func (gw *Gateway) initGenericEventHandlers() {
	conf := gw.GetConfig()
	handlers := make(map[apidef.TykEvent][]config.TykEventHandler)
	for eventName, eventHandlerConfs := range conf.EventHandlers.Events {
		log.Debug("FOUND EVENTS TO INIT")
		for _, handlerConf := range eventHandlerConfs {
			log.Debug("CREATING EVENT HANDLERS")
			eventHandlerInstance, err := gw.EventHandlerByName(handlerConf, nil)

			if err != nil {
				log.Error("Failed to init event handler: ", err)
			} else {
				log.Debug("Init Event Handler: ", eventName)
				handlers[eventName] = append(handlers[eventName], eventHandlerInstance)
			}

		}
	}
	conf.SetEventTriggers(handlers)
	gw.SetConfig(conf)
}
