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
							CoolDownPeriod: ReadableDuration(time.Second * 20),
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
							CoolDownPeriod: ReadableDuration(time.Second * 20),
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
				title: "jsvm events",
				input: EventHandlers{
					{
						Enabled: true,
						Trigger: event.QuotaExceeded,
						Kind:    event.JSVMKind,
						ID:      "random-id",
						Name:    "myQuotaEventHandler",
						JSVMEvent: JSVMEvent{
							FunctionName: "myQuotaEventHandler",
							Path:         "my_script.js",
						},
					},
					{
						Enabled: false,
						Trigger: event.RateLimitExceeded,
						Kind:    event.JSVMKind,
						ID:      "",
						Name:    "myRateLimitEventHandler",
						JSVMEvent: JSVMEvent{
							FunctionName: "myRateLimitEventHandler",
							Path:         "my_script.js",
						},
					},
				},
				expected: apidef.EventHandlerMetaConfig{
					Events: map[event.Event][]apidef.EventHandlerTriggerConfig{
						event.QuotaExceeded: {
							{
								Handler: event.JSVMHandler,
								HandlerMeta: map[string]any{
									"disabled": false,
									"id":       "random-id",
									"name":     "myQuotaEventHandler",
									"path":     "my_script.js",
								},
							},
						},
						event.RateLimitExceeded: {
							{
								Handler: event.JSVMHandler,
								HandlerMeta: map[string]any{
									"disabled": true,
									"id":       "",
									"name":     "myRateLimitEventHandler",
									"path":     "my_script.js",
								},
							},
						},
					},
				},
			},
			{
				title: "log events",
				input: EventHandlers{
					{
						Enabled: true,
						Trigger: event.QuotaExceeded,
						Kind:    event.LogKind,
						ID:      "random-id",
						Name:    "QuotaExceededEvent",
						LogEvent: LogEvent{
							LogPrefix: "QuotaExceededEvent",
						},
					},
					{
						Enabled: false,
						Trigger: event.RateLimitExceeded,
						Kind:    event.LogKind,
						ID:      "",
						Name:    "RateLimitExceededEvent",
						LogEvent: LogEvent{
							LogPrefix: "RateLimitExceededEvent",
						},
					},
				},
				expected: apidef.EventHandlerMetaConfig{
					Events: map[event.Event][]apidef.EventHandlerTriggerConfig{
						event.QuotaExceeded: {
							{
								Handler: event.LogHandler,
								HandlerMeta: map[string]any{
									"disabled": false,
									"prefix":   "QuotaExceededEvent",
								},
							},
						},
						event.RateLimitExceeded: {
							{
								Handler: event.LogHandler,
								HandlerMeta: map[string]any{
									"disabled": true,
									"prefix":   "RateLimitExceededEvent",
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
							CoolDownPeriod: ReadableDuration(time.Second * 20),
							Method:         http.MethodPost,
						},
					},
				},
				expected: apidef.EventHandlerMetaConfig{
					Events: map[apidef.TykEvent][]apidef.EventHandlerTriggerConfig{},
				},
			},
			{
				title: "nil event handlers",
				input: nil,
				expected: apidef.EventHandlerMetaConfig{
					Events: map[apidef.TykEvent][]apidef.EventHandlerTriggerConfig{},
				},
			},
			{
				title: "empty event handlers",
				input: EventHandlers{},
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
			title            string
			existingHandlers EventHandlers
			input            apidef.EventHandlerMetaConfig
			expected         EventHandlers
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
							CoolDownPeriod: ReadableDuration(time.Second * 20),
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
							CoolDownPeriod: ReadableDuration(time.Second * 20),
							Method:         http.MethodPost,
						},
					},
				},
			},
			{
				title: "jsvm event",
				input: apidef.EventHandlerMetaConfig{
					Events: map[event.Event][]apidef.EventHandlerTriggerConfig{
						event.QuotaExceeded: {
							{
								Handler: event.JSVMHandler,
								HandlerMeta: map[string]any{
									"disabled": false,
									"id":       "random-id",
									"name":     "myQuotaEventHandler",
									"path":     "my_script.js",
								},
							},
						},
						event.RateLimitExceeded: {
							{
								Handler: event.JSVMHandler,
								HandlerMeta: map[string]any{
									"disabled": true,
									"id":       "",
									"name":     "myRateLimitEventHandler",
									"path":     "my_script.js",
								},
							},
						},
					},
				},
				expected: EventHandlers{
					{
						Enabled: true,
						Trigger: event.QuotaExceeded,
						Kind:    event.JSVMKind,
						ID:      "random-id",
						Name:    "myQuotaEventHandler",
						JSVMEvent: JSVMEvent{
							FunctionName: "myQuotaEventHandler",
							Path:         "my_script.js",
						},
					},
					{
						Enabled: false,
						Trigger: event.RateLimitExceeded,
						Kind:    event.JSVMKind,
						ID:      "",
						Name:    "myRateLimitEventHandler",
						JSVMEvent: JSVMEvent{
							FunctionName: "myRateLimitEventHandler",
							Path:         "my_script.js",
						},
					},
				},
			},
			{
				title: "log event",
				input: apidef.EventHandlerMetaConfig{
					Events: map[event.Event][]apidef.EventHandlerTriggerConfig{
						event.QuotaExceeded: {
							{
								Handler: event.LogHandler,
								HandlerMeta: map[string]any{
									"disabled": false,
									"prefix":   "QuotaExceededEvent",
								},
							},
						},
						event.RateLimitExceeded: {
							{
								Handler: event.LogHandler,
								HandlerMeta: map[string]any{
									"disabled": true,
									"prefix":   "RateLimitExceededEvent",
								},
							},
						},
					},
				},
				expected: EventHandlers{
					{
						Enabled: true,
						Trigger: event.QuotaExceeded,
						Kind:    event.LogKind,
						ID:      "",
						Name:    "QuotaExceededEvent",
						LogEvent: LogEvent{
							LogPrefix: "QuotaExceededEvent",
						},
					},
					{
						Enabled: false,
						Trigger: event.RateLimitExceeded,
						Kind:    event.LogKind,
						ID:      "",
						Name:    "RateLimitExceededEvent",
						LogEvent: LogEvent{
							LogPrefix: "RateLimitExceededEvent",
						},
					},
				},
			},
			{
				title:    "skip empty actions",
				input:    apidef.EventHandlerMetaConfig{},
				expected: nil,
			},
			{
				title: "set eventHandlers to be empty from classic API def, when OAS is not empty",
				existingHandlers: EventHandlers{
					{
						Enabled: true,
						Trigger: event.BreakerTriggered,
						Kind:    WebhookKind,
						ID:      "random-id",
					},
				},
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
				server := Server{
					EventHandlers: tc.existingHandlers,
				}
				server.EventHandlers.Fill(api)

				assert.ElementsMatch(t, tc.expected, server.EventHandlers)
			})
		}
	})
}

func TestEventHandler_MarshalJSON(t *testing.T) {
	type testCase struct {
		title    string
		input    EventHandler
		expected map[string]any
	}

	testCases := []testCase{
		{
			title: "should marshal webhook event handler",
			input: EventHandler{
				Enabled: true,
				Trigger: event.QuotaExceeded,
				Kind:    event.WebhookKind,
				ID:      "random-id",
				Name:    "test-webhook",
				Webhook: WebhookEvent{
					URL:            "https://webhook.site/uuid",
					Headers:        Headers{{Name: "Auth", Value: "key"}},
					BodyTemplate:   "/path/to/template",
					CoolDownPeriod: ReadableDuration(time.Second * 20),
					Method:         http.MethodPost,
				},
			},
			expected: map[string]any{
				"id":      "random-id",
				"enabled": true,
				"trigger": "QuotaExceeded",
				"type":    "webhook",
				"name":    "test-webhook",
				"url":     "https://webhook.site/uuid",
				"headers": []any{
					map[string]any{
						"name":  "Auth",
						"value": "key",
					},
				},
				"bodyTemplate":   "/path/to/template",
				"cooldownPeriod": "20s",
				"method":         "POST",
			},
		},
		{
			title: "should marshal jsvm event handler",
			input: EventHandler{
				Enabled: true,
				Trigger: event.QuotaExceeded,
				Kind:    event.JSVMKind,
				ID:      "random-id",
				Name:    "test-custom",
				JSVMEvent: JSVMEvent{
					FunctionName: "myCustomEventHandler",
					Path:         "event_handlers/session_editor.js",
				},
			},
			expected: map[string]any{
				"id":           "random-id",
				"enabled":      true,
				"trigger":      "QuotaExceeded",
				"type":         "custom",
				"name":         "test-custom",
				"functionName": "myCustomEventHandler",
				"path":         "event_handlers/session_editor.js",
			},
		},
		{
			title: "should marshal log event handler",
			input: EventHandler{
				Enabled: true,
				Trigger: event.QuotaExceeded,
				Kind:    event.LogKind,
				ID:      "random-id",
				Name:    "test-log",
				LogEvent: LogEvent{
					LogPrefix: "QuotaExceededEvent",
				},
			},
			expected: map[string]any{
				"id":        "random-id",
				"enabled":   true,
				"trigger":   "QuotaExceeded",
				"type":      "log",
				"name":      "test-log",
				"logPrefix": "QuotaExceededEvent",
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.title, func(t *testing.T) {
			data, err := json.Marshal(tc.input)
			assert.NoError(t, err)

			actual := map[string]any{}
			err = json.Unmarshal(data, &actual)
			assert.NoError(t, err)
			assert.EqualValues(t, tc.expected, actual)
		})
	}

}

func TestEventHandler_UnmarshalJSON(t *testing.T) {
	type testCase struct {
		title    string
		input    map[string]any
		expected EventHandler
	}

	testCases := []testCase{
		{
			title: "should unmarshal webhook event handler",
			input: map[string]any{
				"id":      "random-id",
				"enabled": true,
				"trigger": "QuotaExceeded",
				"type":    "webhook",
				"name":    "test-webhook",
				"url":     "https://webhook.site/uuid",
				"headers": []any{
					map[string]any{
						"name":  "Auth",
						"value": "key",
					},
				},
				"bodyTemplate":   "/path/to/template",
				"cooldownPeriod": "20s",
				"method":         "POST",
			},
			expected: EventHandler{
				Enabled: true,
				Trigger: event.QuotaExceeded,
				Kind:    event.WebhookKind,
				ID:      "random-id",
				Name:    "test-webhook",
				Webhook: WebhookEvent{
					URL:            "https://webhook.site/uuid",
					Headers:        Headers{{Name: "Auth", Value: "key"}},
					BodyTemplate:   "/path/to/template",
					CoolDownPeriod: ReadableDuration(time.Second * 20),
					Method:         http.MethodPost,
				},
			},
		},
		{
			title: "should unmarshal jsvm event handler",
			input: map[string]any{
				"id":           "random-id",
				"enabled":      true,
				"trigger":      "QuotaExceeded",
				"type":         "custom",
				"name":         "test-custom",
				"functionName": "myCustomEventHandler",
				"path":         "event_handlers/session_editor.js",
				"body":         "console.log('hello world');",
			},
			expected: EventHandler{
				Enabled: true,
				Trigger: event.QuotaExceeded,
				Kind:    event.JSVMKind,
				ID:      "random-id",
				Name:    "test-custom",
				JSVMEvent: JSVMEvent{
					FunctionName: "myCustomEventHandler",
					Path:         "event_handlers/session_editor.js",
				},
			},
		},
		{
			title: "should unmarshal log event handler",
			input: map[string]any{
				"id":        "random-id",
				"enabled":   true,
				"trigger":   "QuotaExceeded",
				"type":      "log",
				"name":      "test-log",
				"logPrefix": "QuotaExceededEvent",
			},
			expected: EventHandler{
				Enabled: true,
				Trigger: event.QuotaExceeded,
				Kind:    event.LogKind,
				ID:      "random-id",
				Name:    "test-log",
				LogEvent: LogEvent{
					LogPrefix: "QuotaExceededEvent",
				},
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.title, func(t *testing.T) {
			data, err := json.Marshal(tc.input)
			assert.NoError(t, err)

			e := EventHandler{}
			err = json.Unmarshal(data, &e)
			assert.NoError(t, err)

			assert.EqualValues(t, tc.expected, e)
		})
	}
}
