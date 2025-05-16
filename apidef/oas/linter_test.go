package oas

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/service/gojsonschema"
	"github.com/TykTechnologies/tyk/internal/time"
)

func TestXTykGateway_Lint(t *testing.T) {
	var err error

	// Fill structs with data for validation
	settings := XTykAPIGateway{}
	securityScheme := &Basic{}

	Fill(t, &settings, 0)
	Fill(t, &securityScheme, 0)
	{
		settings.Middleware.Global.PluginConfig.Driver = "goplugin"
		for _, op := range settings.Middleware.Operations {
			if op.TransformRequestBody != nil {
				op.TransformRequestBody.Format = "json"
			}
			if op.TransformResponseBody != nil {
				op.TransformResponseBody.Format = "json"
			}
			if op.RateLimit != nil {
				op.RateLimit.Per = ReadableDuration(time.Minute)
			}
			if op.URLRewrite != nil {
				triggers := []*URLRewriteTrigger{}
				for _, cond := range URLRewriteConditions {
					trigger := &URLRewriteTrigger{
						Condition: cond,
						Rules:     []*URLRewriteRule{},
					}
					for _, in := range URLRewriteInputs {
						var rule URLRewriteRule
						if in == InputRequestBody {
							rule = URLRewriteRule{
								In:      in,
								Pattern: ".*",
							}
						} else {
							rule = URLRewriteRule{
								In:      in,
								Name:    "test",
								Pattern: ".*",
							}
						}

						trigger.Rules = append(trigger.Rules, &rule)
					}
					triggers = append(triggers, trigger)
				}
				op.URLRewrite.Triggers = triggers
			}
		}
		settings.Server.Authentication.BaseIdentityProvider = ""
		settings.Server.Authentication.Custom.Config.IDExtractor.Source = "body"
		settings.Server.Authentication.Custom.Config.IDExtractor.With = "regex"
		settings.Server.Authentication.SecuritySchemes = map[string]interface{}{
			"test-basic": securityScheme,
		}
		settings.Server.Protocol = "http"
		settings.Server.Port = 3000
		for i := range settings.Server.EventHandlers {
			settings.Server.EventHandlers[i].Kind = event.WebhookKind
			settings.Server.EventHandlers[i].Webhook.Method = http.MethodPost
			settings.Server.EventHandlers[i].Trigger = event.QuotaExceeded
			settings.Server.EventHandlers[i].Webhook.CoolDownPeriod = ReadableDuration(time.Second * 20)
		}

		for idx := range settings.Middleware.Operations {
			settings.Middleware.Operations[idx].CircuitBreaker.Threshold = 0.5
		}

		settings.Upstream.RateLimit.Per = ReadableDuration(10 * time.Second)
		settings.Server.Authentication.CustomKeyLifetime.Value = ReadableDuration(10 * time.Second)

		settings.Middleware.Global.TrafficLogs.CustomRetentionPeriod = ReadableDuration(10 * time.Second)
		for i := range settings.Middleware.Global.TrafficLogs.Plugins {
			settings.Middleware.Global.TrafficLogs.Plugins[i].RawBodyOnly = false
			settings.Middleware.Global.TrafficLogs.Plugins[i].RequireSession = false
		}

		settings.Upstream.Authentication = &UpstreamAuth{
			Enabled:   false,
			BasicAuth: nil,
			OAuth:     nil,
		}

		settings.Upstream.UptimeTests = &UptimeTests{
			HostDownRetestPeriod: ReadableDuration(10 * time.Second),
			LogRetentionPeriod:   ReadableDuration(10 * time.Second),
			Tests: []UptimeTest{
				{
					Timeout: ReadableDuration(10 * time.Millisecond),
					Commands: []UptimeTestCommand{
						{
							Name:    "send",
							Message: "PING",
						},
						{
							Name:    "recv",
							Message: "+PONG",
						},
					},
					Headers: map[string]string{
						"Request-Id": "1",
					},
				},
			},
		}

		settings.Upstream.TLSTransport.MinVersion = "1.2"
		settings.Upstream.TLSTransport.MaxVersion = "1.2"
		settings.Upstream.TLSTransport.Ciphers = []string{"TLS_RSA_WITH_RC4_128_SHA"}
	}

	// Encode data to json
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	err = enc.Encode(settings)
	require.NoError(t, err)

	// Uncomment for debugging filled/generated json
	// fmt.Println(string(b.Bytes()))

	// Decode back to map
	decoded := make(map[string]interface{})
	err = json.NewDecoder(bytes.NewReader(b.Bytes())).Decode(&decoded)
	require.NoError(t, err)

	// Load schema
	schema, err := schemaDir.ReadFile("schema/x-tyk-api-gateway.strict.json")
	require.NoError(t, err)

	// Run schema validation
	schemaLoader := gojsonschema.NewBytesLoader(schema)
	fileLoader := gojsonschema.NewGoLoader(decoded)

	result, err := gojsonschema.Validate(schemaLoader, fileLoader)
	assert.NoError(t, err)

	errs := result.Errors()
	if len(errs) > 0 {
		for _, err := range errs {
			t.Logf("%s\n", err)
		}
		t.Fail()
	}
}
