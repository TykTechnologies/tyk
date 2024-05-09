package oas

import (
	"encoding/json"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/reflect"
)

// Kind is an alias maintained to be used in imports.
type Kind = event.Kind

// WebhookKind is an alias maintained to be used in imports.
const WebhookKind = event.WebhookKind

// EventHandler holds information about individual event to be configured on the API.
type EventHandler struct {
	// Enabled enables the event handler.
	Enabled bool `json:"enabled" bson:"enabled"`
	// Trigger specifies the TykEvent that should trigger the event handler.
	Trigger event.Event `json:"trigger" bson:"trigger"`
	// Kind specifies the action to be taken on the event trigger.
	Kind Kind `json:"type" bson:"type"` // json tag is changed as per contract
	// ID is the ID of event handler in storage.
	ID string `json:"id,omitempty" bson:"id,omitempty"`
	// Name is the name of event handler
	Name string `json:"name,omitempty" bson:"name,omitempty"`

	Webhook WebhookEvent `bson:"-" json:"-"`
}

// MarshalJSON marshals EventHandler as per Tyk OAS API definition contract.
func (e *EventHandler) MarshalJSON() ([]byte, error) {
	outMap, err := reflect.Cast[map[string]interface{}](*e)
	if err != nil {
		return nil, err
	}

	webhookMap, err := reflect.Cast[map[string]interface{}](e.Webhook)
	if err != nil {
		return nil, err
	}

	outMapVal := *outMap
	for k, v := range *webhookMap {
		outMapVal[k] = v
	}

	return json.Marshal(outMapVal)
}

// UnmarshalJSON unmarshal EventHandler as per Tyk OAS API definition contract.
func (e *EventHandler) UnmarshalJSON(in []byte) error {
	type helperEvent EventHandler
	helper := helperEvent{}
	if err := json.Unmarshal(in, &helper); err != nil {
		return err
	}

	switch helper.Kind {
	case WebhookKind:
		if err := json.Unmarshal(in, &helper.Webhook); err != nil {
			return err
		}
	}

	*e = EventHandler(helper)
	return nil
}

// WebhookEvent stores the core information about a webhook event.
type WebhookEvent struct {
	// URL is the target URL for the webhook.
	URL string `json:"url" bson:"url"`
	// Method is the HTTP method for the webhook.
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
	CoolDownPeriod string `json:"coolDownPeriod" bson:"coolDownPeriod"`
	// BodyTemplate is the template to be used for request payload.
	BodyTemplate string `json:"bodyTemplate,omitempty" bson:"bodyTemplate,omitempty"`
	// Headers are the list of request headers to be used.
	Headers Headers `json:"headers,omitempty" bson:"headers,omitempty"`
}

// GetWebhookConf converts EventHandler.WebhookEvent apidef.WebHookHandlerConf.
func (e *EventHandler) GetWebhookConf() apidef.WebHookHandlerConf {
	coolDownPeriod, err := time.ParseDuration(e.Webhook.CoolDownPeriod)
	if err != nil {
		coolDownPeriod = 0
	}

	return apidef.WebHookHandlerConf{
		Disabled:     !e.Enabled,
		ID:           e.ID,
		Name:         e.Name,
		Method:       e.Webhook.Method,
		TargetPath:   e.Webhook.URL,
		HeaderList:   e.Webhook.Headers.Map(),
		EventTimeout: int64(coolDownPeriod.Seconds()),
		TemplatePath: e.Webhook.BodyTemplate,
	}
}

// EventHandlers holds the list of events to be processed for the API.
type EventHandlers []EventHandler

// Fill fills EventHandlers from classic API definition. Currently only webhook events are supported.
func (e *EventHandlers) Fill(api apidef.APIDefinition) {
	if len(api.EventHandlers.Events) == 0 {
		return
	}

	events := EventHandlers{}
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
						URL:          whConf.TargetPath,
						Method:       whConf.Method,
						Headers:      NewHeaders(whConf.HeaderList),
						BodyTemplate: whConf.TemplatePath,
					},
				}

				if timeout := whConf.EventTimeout; timeout != 0 {
					timeoutDuration := time.Duration(timeout) * time.Second
					ev.Webhook.CoolDownPeriod = timeoutDuration.String()
				}

				events = append(events, ev)
			default:
				continue
			}
		}
	}

	*e = events
}

// ExtractTo extracts events to apidef.APIDefinition.
func (e *EventHandlers) ExtractTo(api *apidef.APIDefinition) {
	if e == nil {
		return
	}

	if len(*e) == 0 {
		return
	}

	if api.EventHandlers.Events == nil {
		api.EventHandlers.Events = make(map[apidef.TykEvent][]apidef.EventHandlerTriggerConfig)
	}

	// this blocks helps with extracting OAS into APIDefinition.
	// update this when new event handlers are added to OAS support.
	for eventType, eventTriggers := range api.EventHandlers.Events {
		triggersExcludingWebhooks := make([]apidef.EventHandlerTriggerConfig, 0)
		for _, eventTrigger := range eventTriggers {
			switch eventTrigger.Handler {
			case event.WebHookHandler:
				continue
			}

			triggersExcludingWebhooks = append(triggersExcludingWebhooks, eventTrigger)
		}

		api.EventHandlers.Events[eventType] = triggersExcludingWebhooks
	}

	for _, ev := range *e {
		var (
			handler     event.HandlerName
			handlerMeta *map[string]interface{}
			err         error
		)

		switch ev.Kind {
		case WebhookKind:
			handler = event.WebHookHandler
			whConf := ev.GetWebhookConf()
			handlerMeta, err = reflect.Cast[map[string]interface{}](whConf)
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
