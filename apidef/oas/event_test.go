package oas

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/time"
)

func TestEventHandlers(t *testing.T) {
	t.Parallel()

	t.Run("extractTo", func(t *testing.T) {
		testcases := []struct {
			title    string
			input    EventHandlers
			expected apidef.EventHandlerMetaConfig
		}{
			{
				title: "webhook",
				input: EventHandlers{
					{
						Enabled: true,
						Trigger: event.QuotaExceeded,
						Kind:    event.WebhookKind,
						ID:      "random-id",
						Name:    "test-webhook",
						Webhook: WebhookEvent{
							URL:            "https://webhook.site/uuid",
							Headers:        Headers{{Name: "Auth", Value: "key"}},
							BodyTemplate:   "/path/to/template",
							CoolDownPeriod: time.ReadableDuration(time.Second * 20),
							Method:         http.MethodPost,
						},
					},
					{
						Enabled: false,
						Trigger: event.RateLimitExceeded,
						Kind:    event.WebhookKind,
						ID:      "random-id",
						Name:    "test-webhook",
						Webhook: WebhookEvent{
							URL:            "https://webhook.site/uuid",
							Headers:        Headers{{Name: "Auth", Value: "key"}},
							BodyTemplate:   "/path/to/template",
							CoolDownPeriod: time.ReadableDuration(time.Second * 20),
							Method:         http.MethodPost,
						},
					},
				},
				expected: apidef.EventHandlerMetaConfig{
					Events: map[event.Event][]apidef.EventHandlerTriggerConfig{
						event.QuotaExceeded: {
							{
								Handler: event.WebHookHandler,
								HandlerMeta: map[string]interface{}{
									"disabled":      false,
									"method":        "POST",
									"template_path": "/path/to/template",
									"header_map":    map[string]interface{}{"Auth": "key"},
									"target_path":   "https://webhook.site/uuid",
									"event_timeout": float64(20),
									"id":            "random-id",
									"name":          "test-webhook",
								},
							},
						},
						event.RateLimitExceeded: {
							{
								Handler: event.WebHookHandler,
								HandlerMeta: map[string]interface{}{
									"disabled":      true,
									"method":        "POST",
									"template_path": "/path/to/template",
									"header_map":    map[string]interface{}{"Auth": "key"},
									"target_path":   "https://webhook.site/uuid",
									"event_timeout": float64(20),
									"id":            "random-id",
									"name":          "test-webhook",
								},
							},
						},
					},
				},
			},
			{
				title: "skip non webhook actions",
				input: EventHandlers{
					{
						Enabled: true,
						Trigger: event.QuotaExceeded,
						Kind:    event.Kind("invalid-action"),
						ID:      "random-id",
						Name:    "test-webhook",
						Webhook: WebhookEvent{
							URL:            "https://webhook.site/uuid",
							Headers:        Headers{{Name: "Auth", Value: "key"}},
							BodyTemplate:   "/path/to/template",
							CoolDownPeriod: time.ReadableDuration(time.Second * 20),
							Method:         http.MethodPost,
						},
					},
				},
				expected: apidef.EventHandlerMetaConfig{
					Events: map[apidef.TykEvent][]apidef.EventHandlerTriggerConfig{},
				},
			},
		}

		for _, tc := range testcases {
			tc := tc
			t.Run(tc.title, func(t *testing.T) {
				t.Parallel()

				server := new(Server)
				server.EventHandlers = tc.input

				var apiDef apidef.APIDefinition
				server.ExtractTo(&apiDef)

				assert.Equal(t, tc.expected, apiDef.EventHandlers)
			})
		}
	})

	t.Run("fill", func(t *testing.T) {
		testcases := []struct {
			title    string
			input    apidef.EventHandlerMetaConfig
			expected EventHandlers
		}{
			{
				title: "webhook",
				input: apidef.EventHandlerMetaConfig{
					Events: map[event.Event][]apidef.EventHandlerTriggerConfig{
						event.QuotaExceeded: {
							{
								Handler: event.WebHookHandler,
								HandlerMeta: map[string]interface{}{
									"disabled":      false,
									"method":        "POST",
									"template_path": "/path/to/template",
									"header_map":    map[string]string{"Auth": "key"},
									"target_path":   "https://webhook.site/uuid",
									"event_timeout": 20,
									"id":            "random-id",
									"name":          "test-webhook",
								},
							},
						},
						event.RateLimitExceeded: {
							{
								Handler: event.WebHookHandler,
								HandlerMeta: map[string]interface{}{
									"disabled":      true,
									"method":        "POST",
									"template_path": "/path/to/template",
									"header_map":    map[string]string{"Auth": "key"},
									"target_path":   "https://webhook.site/uuid",
									"event_timeout": 20,
									"id":            "random-id",
									"name":          "test-webhook",
								},
							},
						},
					},
				},
				expected: EventHandlers{
					{
						Enabled: true,
						Trigger: event.QuotaExceeded,
						Kind:    event.WebhookKind,
						ID:      "random-id",
						Name:    "test-webhook",
						Webhook: WebhookEvent{
							URL:            "https://webhook.site/uuid",
							Headers:        Headers{{Name: "Auth", Value: "key"}},
							BodyTemplate:   "/path/to/template",
							CoolDownPeriod: time.ReadableDuration(time.Second * 20),
							Method:         http.MethodPost,
						},
					},
					{
						Enabled: false,
						Trigger: event.RateLimitExceeded,
						Kind:    event.WebhookKind,
						ID:      "random-id",
						Name:    "test-webhook",
						Webhook: WebhookEvent{
							URL:            "https://webhook.site/uuid",
							Headers:        Headers{{Name: "Auth", Value: "key"}},
							BodyTemplate:   "/path/to/template",
							CoolDownPeriod: time.ReadableDuration(time.Second * 20),
							Method:         http.MethodPost,
						},
					},
				},
			},
			{
				title:    "skip non webhook actions",
				input:    apidef.EventHandlerMetaConfig{},
				expected: nil,
			},
		}

		for _, tc := range testcases {
			tc := tc
			t.Run(tc.title, func(t *testing.T) {
				t.Parallel()

				var api apidef.APIDefinition
				api.EventHandlers = tc.input
				server := new(Server)
				server.EventHandlers.Fill(api)

				assert.ElementsMatch(t, tc.expected, server.EventHandlers)
			})
		}
	})
}

func TestEventHandler_MarshalJSON(t *testing.T) {
	e := EventHandler{
		Enabled: true,
		Trigger: event.QuotaExceeded,
		Kind:    event.WebhookKind,
		ID:      "random-id",
		Name:    "test-webhook",
		Webhook: WebhookEvent{
			URL:            "https://webhook.site/uuid",
			Headers:        Headers{{Name: "Auth", Value: "key"}},
			BodyTemplate:   "/path/to/template",
			CoolDownPeriod: time.ReadableDuration(time.Second * 20),
			Method:         http.MethodPost,
		},
	}

	data, err := json.Marshal(e)
	assert.NoError(t, err)
	expected := map[string]interface{}{
		"id":      "random-id",
		"enabled": true,
		"trigger": "QuotaExceeded",
		"type":    "webhook",
		"name":    "test-webhook",
		"url":     "https://webhook.site/uuid",
		"headers": []interface{}{
			map[string]interface{}{
				"name":  "Auth",
				"value": "key",
			},
		},
		"bodyTemplate":   "/path/to/template",
		"coolDownPeriod": "20s",
		"method":         "POST",
	}

	actual := map[string]interface{}{}
	err = json.Unmarshal(data, &actual)
	assert.NoError(t, err)
	assert.EqualValues(t, expected, actual)
}

func TestEventHandler_UnmarshalJSON(t *testing.T) {
	in := map[string]interface{}{
		"id":      "random-id",
		"enabled": true,
		"trigger": "QuotaExceeded",
		"type":    "webhook",
		"name":    "test-webhook",
		"url":     "https://webhook.site/uuid",
		"headers": []interface{}{
			map[string]interface{}{
				"name":  "Auth",
				"value": "key",
			},
		},
		"bodyTemplate":   "/path/to/template",
		"coolDownPeriod": "20s",
		"method":         "POST",
	}

	data, err := json.Marshal(in)
	assert.NoError(t, err)

	e := EventHandler{}
	err = json.Unmarshal(data, &e)
	assert.NoError(t, err)
	expected := EventHandler{
		Enabled: true,
		Trigger: event.QuotaExceeded,
		Kind:    event.WebhookKind,
		ID:      "random-id",
		Name:    "test-webhook",
		Webhook: WebhookEvent{
			URL:            "https://webhook.site/uuid",
			Headers:        Headers{{Name: "Auth", Value: "key"}},
			BodyTemplate:   "/path/to/template",
			CoolDownPeriod: time.ReadableDuration(time.Second * 20),
			Method:         http.MethodPost,
		},
	}

	assert.EqualValues(t, expected, e)
}
