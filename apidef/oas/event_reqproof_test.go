package oas

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/event"
	tyktime "github.com/TykTechnologies/tyk/internal/time"
)

// Verifies: SYS-REQ-104, SW-REQ-058
// SW-REQ-058:nominal:nominal
// SW-REQ-058:boundary:nominal
// SW-REQ-058:error_handling:nominal
// SW-REQ-058:error_handling:negative
// SW-REQ-058:determinism:nominal
func TestEventHandlersPreserveOASAndClassicShapes(t *testing.T) {
	t.Run("custom JSON embeds kind-specific event fields and decodes them back", func(t *testing.T) {
		handlers := []EventHandler{
			{
				Enabled: true,
				Trigger: event.QuotaExceeded,
				Kind:    WebhookKind,
				ID:      "webhook-id",
				Name:    "quota-webhook",
				Webhook: WebhookEvent{
					URL:            "https://example.test/hook",
					Method:         http.MethodPost,
					CoolDownPeriod: ReadableDuration(20 * tyktime.Second),
					BodyTemplate:   "/templates/quota.json",
					Headers:        Headers{{Name: "Authorization", Value: "secret"}},
				},
			},
			{
				Enabled: true,
				Trigger: event.RateLimitExceeded,
				Kind:    JSVMKind,
				ID:      "jsvm-id",
				Name:    "rate-jsvm",
				JSVMEvent: JSVMEvent{
					FunctionName: "onRateLimit",
					Path:         "middleware/rate.js",
				},
			},
			{
				Enabled: false,
				Trigger: event.BreakerTripped,
				Kind:    LogKind,
				ID:      "log-id",
				Name:    "breaker-log",
				LogEvent: LogEvent{
					LogPrefix: "breaker",
				},
			},
		}

		for _, handler := range handlers {
			payload, err := json.Marshal(handler)
			require.NoError(t, err)

			var decoded EventHandler
			require.NoError(t, json.Unmarshal(payload, &decoded))
			assert.Equal(t, handler, decoded)
		}
	})

	t.Run("invalid JSON is rejected without mutating the receiver", func(t *testing.T) {
		handler := EventHandler{Enabled: true, Kind: WebhookKind, ID: "unchanged"}

		err := handler.UnmarshalJSON([]byte(`{"enabled":`))

		require.Error(t, err)
		assert.Equal(t, EventHandler{Enabled: true, Kind: WebhookKind, ID: "unchanged"}, handler)
	})

	t.Run("direct handler config extraction preserves Classic fields", func(t *testing.T) {
		webhook := EventHandler{
			Enabled: false,
			ID:      "webhook-id",
			Name:    "quota-webhook",
			Webhook: WebhookEvent{
				URL:            "https://example.test/hook",
				Method:         http.MethodPut,
				CoolDownPeriod: ReadableDuration(11 * tyktime.Second),
				BodyTemplate:   "/templates/body.json",
				Headers:        Headers{{Name: "X-Test", Value: "true"}},
			},
		}
		webhookConf := webhook.GetWebhookConf()
		assert.True(t, webhookConf.Disabled)
		assert.Equal(t, "webhook-id", webhookConf.ID)
		assert.Equal(t, "quota-webhook", webhookConf.Name)
		assert.Equal(t, "https://example.test/hook", webhookConf.TargetPath)
		assert.Equal(t, http.MethodPut, webhookConf.Method)
		assert.Equal(t, int64(11), webhookConf.EventTimeout)
		assert.Equal(t, "/templates/body.json", webhookConf.TemplatePath)
		assert.Equal(t, map[string]string{"X-Test": "true"}, webhookConf.HeaderList)

		jsvm := EventHandler{Enabled: true, ID: "jsvm-id", JSVMEvent: JSVMEvent{FunctionName: "onQuota", Path: "quota.js"}}
		jsvmConf := jsvm.GetJSVMEventHandlerConf()
		assert.False(t, jsvmConf.Disabled)
		assert.Equal(t, "jsvm-id", jsvmConf.ID)
		assert.Equal(t, "onQuota", jsvmConf.MethodName)
		assert.Equal(t, "quota.js", jsvmConf.Path)

		logHandler := EventHandler{Enabled: false, LogEvent: LogEvent{LogPrefix: "prefix"}}
		logConf := logHandler.GetLogEventHandlerConf()
		assert.True(t, logConf.Disabled)
		assert.Equal(t, "prefix", logConf.Prefix)
	})

	t.Run("Fill imports supported Classic handlers and skips unsupported handlers", func(t *testing.T) {
		api := apidef.APIDefinition{
			EventHandlers: apidef.EventHandlerMetaConfig{
				Events: map[event.Event][]apidef.EventHandlerTriggerConfig{
					event.QuotaExceeded: {
						{
							Handler: event.WebHookHandler,
							HandlerMeta: map[string]any{
								"disabled":      false,
								"id":            "webhook-id",
								"name":          "quota-webhook",
								"method":        http.MethodPost,
								"target_path":   "https://example.test/hook",
								"template_path": "/templates/quota.json",
								"event_timeout": 20,
								"header_map":    map[string]string{"Authorization": "secret"},
							},
						},
						{Handler: event.HandlerName("unsupported"), HandlerMeta: map[string]any{"keep": true}},
					},
					event.RateLimitExceeded: {
						{
							Handler: event.JSVMHandler,
							HandlerMeta: map[string]any{
								"disabled": false,
								"id":       "jsvm-id",
								"name":     "onRateLimit",
								"path":     "rate.js",
							},
						},
					},
					event.BreakerTripped: {
						{
							Handler: event.LogHandler,
							HandlerMeta: map[string]any{
								"disabled": true,
								"prefix":   "breaker",
							},
						},
					},
				},
			},
		}

		var handlers EventHandlers
		handlers.Fill(api)

		require.Len(t, handlers, 3)
		assert.ElementsMatch(t, EventHandlers{
			{
				Enabled: true,
				Trigger: event.QuotaExceeded,
				Kind:    WebhookKind,
				ID:      "webhook-id",
				Name:    "quota-webhook",
				Webhook: WebhookEvent{
					URL:            "https://example.test/hook",
					Method:         http.MethodPost,
					CoolDownPeriod: ReadableDuration(20 * tyktime.Second),
					BodyTemplate:   "/templates/quota.json",
					Headers:        Headers{{Name: "Authorization", Value: "secret"}},
				},
			},
			{
				Enabled: true,
				Trigger: event.RateLimitExceeded,
				Kind:    JSVMKind,
				ID:      "jsvm-id",
				Name:    "onRateLimit",
				JSVMEvent: JSVMEvent{
					FunctionName: "onRateLimit",
					Path:         "rate.js",
				},
			},
			{
				Enabled:  false,
				Trigger:  event.BreakerTripped,
				Kind:     LogKind,
				Name:     "breaker",
				LogEvent: LogEvent{LogPrefix: "breaker"},
			},
		}, handlers)

		handlers.Fill(apidef.APIDefinition{})
		assert.Empty(t, handlers)
	})

	t.Run("ExtractTo replaces supported handlers and preserves unsupported existing handlers", func(t *testing.T) {
		api := &apidef.APIDefinition{
			EventHandlers: apidef.EventHandlerMetaConfig{
				Events: map[event.Event][]apidef.EventHandlerTriggerConfig{
					event.QuotaExceeded: {
						{Handler: event.WebHookHandler, HandlerMeta: map[string]any{"target_path": "old"}},
						{Handler: event.HandlerName("external"), HandlerMeta: map[string]any{"keep": "yes"}},
					},
				},
			},
		}

		handlers := EventHandlers{
			{
				Enabled: true,
				Trigger: event.QuotaExceeded,
				Kind:    WebhookKind,
				ID:      "new-webhook",
				Name:    "new",
				Webhook: WebhookEvent{
					URL:            "https://example.test/new",
					Method:         http.MethodPatch,
					CoolDownPeriod: ReadableDuration(7 * tyktime.Second),
					Headers:        Headers{{Name: "X-New", Value: "true"}},
				},
			},
			{
				Enabled: true,
				Trigger: event.RateLimitExceeded,
				Kind:    event.Kind("unknown"),
			},
		}

		handlers.ExtractTo(api)

		quotaHandlers := api.EventHandlers.Events[event.QuotaExceeded]
		require.Len(t, quotaHandlers, 2)
		assert.Equal(t, event.HandlerName("external"), quotaHandlers[0].Handler)
		assert.Equal(t, map[string]any{"keep": "yes"}, quotaHandlers[0].HandlerMeta)
		assert.Equal(t, event.WebHookHandler, quotaHandlers[1].Handler)
		assert.Equal(t, "https://example.test/new", quotaHandlers[1].HandlerMeta["target_path"])
		assert.Equal(t, http.MethodPatch, quotaHandlers[1].HandlerMeta["method"])
		assert.Equal(t, float64(7), quotaHandlers[1].HandlerMeta["event_timeout"])
		assert.Equal(t, "new-webhook", quotaHandlers[1].HandlerMeta["id"])
		assert.NotContains(t, api.EventHandlers.Events, event.RateLimitExceeded)

		var nilHandlers *EventHandlers
		nilHandlers.ExtractTo(api)
		require.Len(t, api.EventHandlers.Events[event.QuotaExceeded], 1)
		assert.Equal(t, event.HandlerName("external"), api.EventHandlers.Events[event.QuotaExceeded][0].Handler)
		assert.Equal(t, map[string]any{"keep": "yes"}, api.EventHandlers.Events[event.QuotaExceeded][0].HandlerMeta)
	})
}
