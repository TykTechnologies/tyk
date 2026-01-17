package gateway

import (
	"errors"
	"fmt"
	"time"

	"github.com/TykTechnologies/tyk/internal/event"

	circuit "github.com/TykTechnologies/circuitbreaker"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

const (
	// EH_WebHook is an alias maintained for backwards compatibility.
	// it is the handler to register a webhook event.
	EH_WebHook = event.WebHookHandler
	// EH_JSVMHandler is aliased for backwards compatibility.
	EH_JSVMHandler = event.JSVMHandler
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
	// EventUpstreamOAuthError is an alias maintained for backwards compatibility.
	UpstreamOAuthError = event.UpstreamOAuthError
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
	// EventCertificateExpiringSoon is an alias maintained for backwards compatibility.
	EventCertificateExpiringSoon = event.CertificateExpiringSoon
	// EventCertificateExpired is an alias maintained for backwards compatibility.
	EventCertificateExpired = event.CertificateExpired
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

func (e *EventKeyFailureMeta) LogMessage(prefix string) string {
	return fmt.Sprintf("%s:%s:%s:%s", prefix, e.Key, e.Origin, e.Path)
}

// EventCurcuitBreakerMeta is the event status for a circuit breaker tripping
type EventCurcuitBreakerMeta struct {
	EventMetaDefault
	Path         string
	APIID        string
	CircuitEvent circuit.BreakerEvent
}

func (e *EventCurcuitBreakerMeta) LogMessage(prefix string) string {
	return fmt.Sprintf("%s:%s:%s: [STATUS] %s", prefix, e.APIID, e.Path, fmt.Sprint(e.CircuitEvent))
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
	log.Debugf("EVENT TRIGGERS MAP SIZE: %d", len(handlers))

	// Log only event names (keys), not the full handler configuration which may contain sensitive data
	// such as webhook URLs, headers with authentication tokens, or other credentials
	eventNames := make([]apidef.TykEvent, 0, len(handlers))
	for eventName := range handlers {
		eventNames = append(eventNames, eventName)
	}
	log.Debugf("REGISTERED EVENT TYPES: %v", eventNames)

	if handlers, e := handlers[name]; e {
		log.Debugf("FOUND %d EVENT HANDLERS FOR %s", len(handlers), name)
		eventMessage := config.EventMessage{
			Meta:      meta,
			Type:      name,
			TimeStamp: time.Now().Local().String(),
		}
		for i, handler := range handlers {
			log.Debugf("FIRING HANDLER %d/%d FOR EVENT %s", i+1, len(handlers), name)
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
