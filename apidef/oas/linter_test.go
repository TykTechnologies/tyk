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

// fixSingleOperation fixes a single operation's fields to pass schema validation.
// This is needed because Fill() populates fields with random test data that may not
// conform to schema constraints (e.g., duration formats, enum values).
func fixSingleOperation(op *Operation) {
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
	if op.CircuitBreaker != nil {
		op.CircuitBreaker.Threshold = 0.5
	}
}

// fixOperationsForValidation fixes operation fields in an Operations map to pass schema validation.
func fixOperationsForValidation(operations map[string]*Operation) {
	for _, op := range operations {
		fixSingleOperation(op)
	}
}

// fixMCPPrimitivesForValidation fixes operation fields in an MCPPrimitives map to pass schema validation.
func fixMCPPrimitivesForValidation(primitives map[string]*MCPPrimitive) {
	for _, prim := range primitives {
		fixSingleOperation(&prim.Operation)
	}
}

func TestXTykGateway_Lint(t *testing.T) {
	var err error

	// Fill structs with data for validation
	settings := XTykAPIGateway{}
	securityScheme := &Basic{}

	Fill(t, &settings, 0)
	Fill(t, &securityScheme, 0)
	{
		settings.Middleware.Global.PluginConfig.Driver = "goplugin"
		fixOperationsForValidation(settings.Middleware.Operations)
		fixMCPPrimitivesForValidation(settings.Middleware.McpTools)
		fixMCPPrimitivesForValidation(settings.Middleware.McpResources)
		fixMCPPrimitivesForValidation(settings.Middleware.McpPrompts)

		settings.Server.Authentication.BaseIdentityProvider = ""
		settings.Server.Authentication.SecurityProcessingMode = SecurityProcessingModeLegacy
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

		if settings.Info.Versioning != nil {
			switch settings.Info.Versioning.Location {
			case "header", "url-param", "url":
			default:
				settings.Info.Versioning.Location = "header"
			}
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

func TestVersioningSchemaValidation(t *testing.T) {
	schema, err := schemaDir.ReadFile("schema/x-tyk-api-gateway.strict.json")
	require.NoError(t, err)
	schemaLoader := gojsonschema.NewBytesLoader(schema)

	createBaseAPIGateway := func() XTykAPIGateway {
		return XTykAPIGateway{
			Info: Info{
				Name: "Test API",
				State: State{
					Active: true,
				},
			},
			Upstream: Upstream{
				URL: "http://example.com",
			},
			Server: Server{
				ListenPath: ListenPath{
					Value: "/test",
				},
			},
		}
	}

	tests := []struct {
		name            string
		setupVersioning func() *Versioning
		shouldBeValid   bool
	}{
		{
			name: "valid with header location and key",
			setupVersioning: func() *Versioning {
				return &Versioning{
					Enabled:  true,
					Location: "header",
					Key:      "x-api-version",
					Versions: []VersionToID{
						{Name: "v1", ID: "version-1"},
					},
				}
			},
			shouldBeValid: true,
		},
		{
			name: "valid with url location without key",
			setupVersioning: func() *Versioning {
				return &Versioning{
					Enabled:  true,
					Location: "url",
					Versions: []VersionToID{
						{Name: "v1", ID: "version-1"},
					},
				}
			},
			shouldBeValid: true,
		},
		{
			name: "invalid with header location without key",
			setupVersioning: func() *Versioning {
				return &Versioning{
					Enabled:  true,
					Location: "header",
					Versions: []VersionToID{
						{Name: "v1", ID: "version-1"},
					},
				}
			},
			shouldBeValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			apiGateway := createBaseAPIGateway()
			apiGateway.Info.Versioning = tc.setupVersioning()

			docLoader := gojsonschema.NewGoLoader(apiGateway)
			result, err := gojsonschema.Validate(schemaLoader, docLoader)
			assert.NoError(t, err)

			if tc.shouldBeValid {
				if !result.Valid() {
					t.Errorf("Expected schema to be valid but got errors: %v", result.Errors())
				}
			} else {
				if result.Valid() {
					t.Errorf("Expected schema to be invalid but it was valid")
				}
			}
		})
	}
}
