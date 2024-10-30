package gateway

import (
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/event"

	circuit "github.com/TykTechnologies/circuitbreaker"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

// The name for event handlers as defined in the API Definition JSON/BSON format
const (
	// EH_LogHandler is an alias maintained for backwards compatibility.
	// It is used to register log handler on an event.
	EH_LogHandler = event.LogHandler
)

const (
	// EventQuotaExceeded is an alias maintained for backwards compatibility.
	EventQuotaExceeded = event.QuotaExceeded
	// RateLimitExceeded is an alias maintained for backwards compatibility.
	EventRateLimitExceeded = event.RateLimitExceeded
	// EventAuthFailure is an alias maintained for backwards compatibility.
	EventAuthFailure = event.AuthFailure
	// EventKeyExpired is an alias maintained for backwards compatibility.
	EventKeyExpired = event.KeyExpired
	// EventVersionFailure is an alias maintained for backwards compatibility.
	EventVersionFailure = event.VersionFailure
	// EventOrgQuotaExceeded is an alias maintained for backwards compatibility.
	EventOrgQuotaExceeded = event.OrgQuotaExceeded
	// EventOrgRateLimitExceeded is an alias maintained for backwards compatibility.
	EventOrgRateLimitExceeded = event.OrgRateLimitExceeded
	// EventTriggerExceeded is an alias maintained for backwards compatibility.
	EventTriggerExceeded = event.TriggerExceeded
	// EventBreakerTriggered is an alias maintained for backwards compatibility.
	EventBreakerTriggered = event.BreakerTriggered
	// EventBreakerTripped is an alias maintained for backwards compatibility.
	EventBreakerTripped = event.BreakerTripped
	// EventBreakerReset is an alias maintained for backwards compatibility.
	EventBreakerReset = event.BreakerReset
	// EventHOSTDOWN is an alias maintained for backwards compatibility.
	EventHOSTDOWN = event.HostDown
	// EventHOSTUP is an alias maintained for backwards compatibility.
	EventHOSTUP = event.HostUp
	// EventTokenCreated is an alias maintained for backwards compatibility.
	EventTokenCreated = event.TokenCreated
	// EventTokenUpdated is an alias maintained for backwards compatibility.
	EventTokenUpdated = event.TokenUpdated
	// EventTokenDeleted is an alias maintained for backwards compatibility.
	EventTokenDeleted = event.TokenDeleted
)

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
