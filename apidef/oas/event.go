package oas

import (
	"encoding/json"
	"maps"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/reflect"
	"github.com/TykTechnologies/tyk/internal/time"
)

// Kind is an alias maintained to be used in imports.
type Kind = event.Kind

// WebhookKind is an alias maintained to be used in imports.
const (
	WebhookKind = event.WebhookKind
	JSVMKind    = event.JSVMKind
	LogKind     = event.LogKind
)

// EventHandler holds information about individual event to be configured on the API.
type EventHandler struct {
	// Enabled enables the event handler.
	//
	// Tyk classic API definition: `event_handlers.events[].handler_meta.disabled` (negated).
	Enabled bool `json:"enabled" bson:"enabled"`
	// Trigger specifies the TykEvent that should trigger the event handler.
	//
	// Tyk classic API definition: `event_handlers.events` key.
	Trigger event.Event `json:"trigger" bson:"trigger"`
	// Kind specifies the action to be taken on the event trigger.
	//
	// Tyk classic API definition: `event_handlers.events[].handler`.
	Kind Kind `json:"type" bson:"type"` // json tag is changed as per contract
	// ID is the ID of event handler in storage.
	//
	// Tyk classic API definition: `event_handlers.events[].handler_meta.id`.
	ID string `json:"id,omitempty" bson:"id,omitempty"`
	// Name is the name of event handler.
	//
	// Tyk classic API definition: `event_handlers.events[].handler_meta.name`.
	Name string `json:"name,omitempty" bson:"name,omitempty"`

	// Webhook contains WebhookEvent configs. Encoding and decoding is handled by the custom marshaller.
	Webhook WebhookEvent `bson:"-" json:"-"`

	// JSVMEvent holds information about JavaScript VM events.
	JSVMEvent JSVMEvent `bson:"-" json:"-"`

	// LogEvent represents the configuration for logging events tied to an event handler.
	LogEvent LogEvent `bson:"-" json:"-"`
}

// MarshalJSON marshals EventHandler as per Tyk OAS API definition contract.
func (e EventHandler) MarshalJSON() ([]byte, error) {
	type helperEventHandler EventHandler
	helper := helperEventHandler(e)

	outMap, err := reflect.Cast[map[string]any](helper)
	if err != nil {
		return nil, err
	}

	outMapVal := *outMap

	switch helper.Kind {
	case WebhookKind:
		webhookMap, err := reflect.Cast[map[string]any](helper.Webhook)
		if err != nil {
			return nil, err
		}
		maps.Insert(outMapVal, maps.All(*webhookMap))
	case JSVMKind:
		jsvmMap, err := reflect.Cast[map[string]any](helper.JSVMEvent)
		if err != nil {
			return nil, err
		}
		maps.Insert(outMapVal, maps.All(*jsvmMap))
	case LogKind:
		logMap, err := reflect.Cast[map[string]any](helper.LogEvent)
		if err != nil {
			return nil, err
		}
		maps.Insert(outMapVal, maps.All(*logMap))
	}

	return json.Marshal(outMapVal)
}

// UnmarshalJSON unmarshal EventHandler as per Tyk OAS API definition contract.
func (e *EventHandler) UnmarshalJSON(in []byte) error {
	type helperEventHandler EventHandler
	helper := helperEventHandler{}
	if err := json.Unmarshal(in, &helper); err != nil {
		return err
	}

	switch helper.Kind {
	case WebhookKind:
		if err := json.Unmarshal(in, &helper.Webhook); err != nil {
			return err
		}
	case JSVMKind:
		if err := json.Unmarshal(in, &helper.JSVMEvent); err != nil {
			return err
		}
	case LogKind:
		if err := json.Unmarshal(in, &helper.LogEvent); err != nil {
			return err
		}
	}

	*e = EventHandler(helper)
	return nil
}

// WebhookEvent stores the core information about a webhook event.
type WebhookEvent struct {
	// URL is the target URL for the webhook.
	//
	// Tyk classic API definition: `event_handlers.events[].handler_meta.target_path`.
	URL string `json:"url" bson:"url"`
	// Method is the HTTP method for the webhook.
	//
	// Tyk classic API definition: `event_handlers.events[].handler_meta.method`.
	Method string `json:"method" bson:"method"`
	// CoolDownPeriod defines cool-down for the event, so it does not trigger again.
	// It uses shorthand notation.
	// The value of CoolDownPeriod is a string that specifies the interval in a compact form,
	// where hours, minutes and seconds are denoted by 'h', 'm' and 's' respectively.
	// Multiple units can be combined to represent the duration.
	//
	// Examples of valid shorthand notations:
	// - "1h"   : one hour
	// - "20m"  : twenty minutes
	// - "30s"  : thirty seconds
	// - "1m29s": one minute and twenty-nine seconds
	// - "1h30m" : one hour and thirty minutes
	//
	// An empty value is interpreted as "0s", implying no cool-down.
	// It's important to format the string correctly, as invalid formats will
	// be considered as 0s/empty.
	//
	// Tyk classic API definition: `event_handlers.events[].handler_meta.event_timeout`.
	CoolDownPeriod ReadableDuration `json:"cooldownPeriod" bson:"cooldownPeriod"`
	// BodyTemplate is the template to be used for request payload.
	//
	// Tyk classic API definition: `event_handlers.events[].handler_meta.template_path`.
	BodyTemplate string `json:"bodyTemplate,omitempty" bson:"bodyTemplate,omitempty"`
	// Headers are the list of request headers to be used.
	//
	// Tyk classic API definition: `event_handlers.events[].handler_meta.header_map`.
	Headers Headers `json:"headers,omitempty" bson:"headers,omitempty"`
}

// GetWebhookConf converts EventHandler.WebhookEvent apidef.WebHookHandlerConf.
func (e *EventHandler) GetWebhookConf() apidef.WebHookHandlerConf {
	return apidef.WebHookHandlerConf{
		Disabled:     !e.Enabled,
		ID:           e.ID,
		Name:         e.Name,
		Method:       e.Webhook.Method,
		TargetPath:   e.Webhook.URL,
		HeaderList:   e.Webhook.Headers.Map(),
		EventTimeout: int64(e.Webhook.CoolDownPeriod.Seconds()),
		TemplatePath: e.Webhook.BodyTemplate,
	}
}

// JSVMEvent represents a JavaScript VM event configuration for event handlers.
type JSVMEvent struct {
	// FunctionName specifies the JavaScript function name to be executed.
	//
	// Tyk classic API definition: `event_handlers.events[].handler_meta.method_name`.
	FunctionName string `json:"functionName" bson:"functionName"`
	// Path specifies the path to the JavaScript file containing the function.
	//
	// Tyk classic API definition: `event_handlers.events[].handler_meta.path`.
	Path string `json:"path" bson:"path"`
}

// GetJSVMEventHandlerConf generates the JavaScript VM event handler configuration using the current EventHandler instance.
func (e *EventHandler) GetJSVMEventHandlerConf() apidef.JSVMEventHandlerConf {
	return apidef.JSVMEventHandlerConf{
		Disabled:   !e.Enabled,
		ID:         e.ID,
		MethodName: e.JSVMEvent.FunctionName,
		Path:       e.JSVMEvent.Path,
	}
}

// LogEvent represents the configuration for logging events within an event handler.
type LogEvent struct {
	// LogPrefix defines the prefix used for log messages in the logging event.
	//
	// Tyk classic API definition: `event_handlers.events[].handler_meta.prefix`.
	LogPrefix string `json:"logPrefix" bson:"logPrefix"`
}

// GetLogEventHandlerConf creates and returns a LogEventHandlerConf based on the current EventHandler configuration.
func (e *EventHandler) GetLogEventHandlerConf() apidef.LogEventHandlerConf {
	return apidef.LogEventHandlerConf{
		Disabled: !e.Enabled,
		Prefix:   e.LogEvent.LogPrefix,
	}
}

// EventHandlers holds the list of events to be processed for the API.
type EventHandlers []EventHandler

// Fill fills EventHandlers from classic API definition. Currently only webhook and jsvm events are supported.
func (e *EventHandlers) Fill(api apidef.APIDefinition) {
	events := EventHandlers{}
	if len(api.EventHandlers.Events) == 0 {
		*e = events
		return
	}

	for gwEvent, ehs := range api.EventHandlers.Events {
		for _, eh := range ehs {
			switch eh.Handler {
			case event.WebHookHandler:
				whConf := apidef.WebHookHandlerConf{}
				err := whConf.Scan(eh.HandlerMeta)
				if err != nil {
					continue
				}

				ev := EventHandler{
					Enabled: !whConf.Disabled,
					Trigger: gwEvent,
					Kind:    WebhookKind,
					ID:      whConf.ID,
					Name:    whConf.Name,
					Webhook: WebhookEvent{
						URL:            whConf.TargetPath,
						Method:         whConf.Method,
						Headers:        NewHeaders(whConf.HeaderList),
						BodyTemplate:   whConf.TemplatePath,
						CoolDownPeriod: ReadableDuration(time.Duration(whConf.EventTimeout) * time.Second),
					},
				}

				events = append(events, ev)
			case event.JSVMHandler:
				jsvmHandlerConf := apidef.JSVMEventHandlerConf{}
				err := jsvmHandlerConf.Scan(eh.HandlerMeta)
				if err != nil {
					continue
				}

				ev := EventHandler{
					Enabled: !jsvmHandlerConf.Disabled,
					Trigger: gwEvent,
					Kind:    JSVMKind,
					ID:      jsvmHandlerConf.ID,
					Name:    jsvmHandlerConf.MethodName, // jsvm events don't have human-readable names, let's reuse the methodName
					JSVMEvent: JSVMEvent{
						FunctionName: jsvmHandlerConf.MethodName,
						Path:         jsvmHandlerConf.Path,
					},
				}

				events = append(events, ev)
			case event.LogHandler:
				logHandlerConf := apidef.LogEventHandlerConf{}
				err := logHandlerConf.Scan(eh.HandlerMeta)
				if err != nil {
					continue
				}

				ev := EventHandler{
					Enabled: !logHandlerConf.Disabled,
					Trigger: gwEvent,
					Kind:    LogKind,
					Name:    logHandlerConf.Prefix, // log events don't have human-readable names, let's reuse the prefix
					LogEvent: LogEvent{
						LogPrefix: logHandlerConf.Prefix,
					},
				}

				events = append(events, ev)
			default:
				continue
			}
		}
	}

	*e = events
}

// ExtractTo EventHandlers events to apidef.APIDefinition.
func (e *EventHandlers) ExtractTo(api *apidef.APIDefinition) {
	if api.EventHandlers.Events == nil {
		api.EventHandlers.Events = make(map[apidef.TykEvent][]apidef.EventHandlerTriggerConfig)
	}

	resetOASSupportedEventHandlers(api)

	if e == nil {
		return
	}

	if len(*e) == 0 {
		return
	}

	for _, ev := range *e {
		var (
			handler     event.HandlerName
			handlerMeta *map[string]any
			err         error
		)

		switch ev.Kind {
		case WebhookKind:
			handler = event.WebHookHandler
			whConf := ev.GetWebhookConf()
			handlerMeta, err = reflect.Cast[map[string]any](whConf)
		case JSVMKind:
			handler = event.JSVMHandler
			jsvmConf := ev.GetJSVMEventHandlerConf()
			handlerMeta, err = reflect.Cast[map[string]any](jsvmConf)
		case LogKind:
			handler = event.LogHandler
			logConf := ev.GetLogEventHandlerConf()
			handlerMeta, err = reflect.Cast[map[string]any](logConf)
		default:
			continue
		}

		if err != nil {
			log.WithError(err).Error("error converting event to map")
			continue
		}

		eventHandlerTriggerConfig := apidef.EventHandlerTriggerConfig{
			Handler:     handler,
			HandlerMeta: *handlerMeta,
		}

		if val, ok := api.EventHandlers.Events[ev.Trigger]; ok {
			api.EventHandlers.Events[ev.Trigger] = append(val, eventHandlerTriggerConfig)
			continue
		}

		api.EventHandlers.Events[ev.Trigger] = []apidef.EventHandlerTriggerConfig{eventHandlerTriggerConfig}
	}
}

func resetOASSupportedEventHandlers(api *apidef.APIDefinition) {
	// this blocks helps with extracting OAS into APIDefinition.
	// update this when new event handlers are added to OAS support.
	eventHandlers := map[apidef.TykEvent][]apidef.EventHandlerTriggerConfig{}
	for eventType, eventTriggers := range api.EventHandlers.Events {
		triggersExcludingWebhooks := make([]apidef.EventHandlerTriggerConfig, 0)
		for _, eventTrigger := range eventTriggers {
			switch eventTrigger.Handler {
			case event.WebHookHandler, event.JSVMHandler, event.LogHandler:
				continue
			}

			triggersExcludingWebhooks = append(triggersExcludingWebhooks, eventTrigger)
		}

		if len(triggersExcludingWebhooks) > 0 {
			eventHandlers[eventType] = triggersExcludingWebhooks
		}
	}

	api.EventHandlers.Events = eventHandlers
}
