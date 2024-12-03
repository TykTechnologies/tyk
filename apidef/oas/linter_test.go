package oas

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"

	"github.com/TykTechnologies/tyk/internal/event"
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

		settings.Upstream.Authentication = &UpstreamAuth{
			Enabled:   false,
			BasicAuth: nil,
			OAuth:     nil,
		}
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
	schema, err := os.ReadFile("schema/x-tyk-api-gateway.json")
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
