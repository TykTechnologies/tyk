package oas

import (
	"encoding/json"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/reflect"
)

type Kind = event.Kind

const WebhookKind = event.WebhookKind

// Event holds information about individual event to be configured on the API.
type Event struct {
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

// MarshalJSON marshals Event as per Tyk OAS API definition contract.
func (e *Event) MarshalJSON() ([]byte, error) {
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

// UnmarshalJSON unmarshal Event as per Tyk OAS API definition contract.
func (e *Event) UnmarshalJSON(in []byte) error {
	type helperEvent Event
	helper := helperEvent{}
	if err := json.Unmarshal(in, &helper); err != nil {
		return err
	}

	if err := json.Unmarshal(in, &helper.Webhook); err != nil {
		return err
	}

	*e = Event(helper)
	return nil
}

// WebhookEvent stores the core information about a webhook event.
type WebhookEvent struct {
	URL          string  `json:"url" bson:"url"`
	Method       string  `json:"method" bson:"method"`
	Timeout      int64   `json:"timeout" bson:"timeout"`
	BodyTemplate string  `json:"bodyTemplate,omitempty" bson:"bodyTemplate,omitempty"`
	Headers      Headers `json:"headers,omitempty" bson:"headers,omitempty"`
}

// GetWebhookConf converts Event.WebhookEvent apidef.WebHookHandlerConf.
func (e *Event) GetWebhookConf() apidef.WebHookHandlerConf {
	return apidef.WebHookHandlerConf{
		Disabled:     !e.Enabled,
		ID:           e.ID,
		Name:         e.Name,
		Method:       e.Webhook.Method,
		TargetPath:   e.Webhook.URL,
		HeaderList:   e.Webhook.Headers.Map(),
		EventTimeout: e.Webhook.Timeout,
		TemplatePath: e.Webhook.BodyTemplate,
	}
}

// Events holds the list of events to be processed for the API.
type Events []Event

// Fill fills Events from classic API definition. Currently only webhook events are supported.
func (e *Events) Fill(api apidef.APIDefinition) {
	if len(api.EventHandlers.Events) == 0 {
		return
	}

	events := Events{}
	for gwEvent, ehs := range api.EventHandlers.Events {
		for _, eh := range ehs {
			if eh.Handler != event.WebHookHandler {
				continue
			}

			whConf := apidef.WebHookHandlerConf{}
			err := whConf.Scan(eh.HandlerMeta)
			if err != nil {
				continue
			}

			ev := Event{
				Enabled: !whConf.Disabled,
				Trigger: gwEvent,
				Kind:    WebhookKind,
				ID:      whConf.ID,
				Name:    whConf.Name,
				Webhook: WebhookEvent{

					URL:          whConf.TargetPath,
					Method:       whConf.Method,
					Headers:      NewHeaders(whConf.HeaderList),
					Timeout:      whConf.EventTimeout,
					BodyTemplate: whConf.TemplatePath,
				},
			}

			events = append(events, ev)
		}
	}

	*e = events
}

// ExtractTo extracts events to apidef.APIDefinition.
func (e *Events) ExtractTo(api *apidef.APIDefinition) {
	if e == nil || len(*e) == 0 {
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
			if eventTrigger.Handler == event.WebHookHandler {
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
