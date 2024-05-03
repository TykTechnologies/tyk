package oas

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	tykevent "github.com/TykTechnologies/tyk/pkg/event"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestServer(t *testing.T) {
	t.Parallel()

	var emptyServer Server

	var convertedAPI apidef.APIDefinition
	convertedAPI.SetDisabledFlags()
	emptyServer.ExtractTo(&convertedAPI)

	var resultServer Server
	resultServer.Fill(convertedAPI)

	assert.Equal(t, emptyServer, resultServer)
}

func TestListenPath(t *testing.T) {
	t.Parallel()

	var emptyListenPath ListenPath

	var convertedAPI apidef.APIDefinition
	emptyListenPath.ExtractTo(&convertedAPI)

	var resultListenPath ListenPath
	resultListenPath.Fill(convertedAPI)

	assert.Equal(t, emptyListenPath, resultListenPath)
}

func TestGatewayTags(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		input GatewayTags
		want  GatewayTags
		omit  bool
	}{
		{
			input: GatewayTags{},
			want:  GatewayTags{},
			omit:  true,
		},
		{
			input: GatewayTags{Enabled: true},
			want:  GatewayTags{Enabled: true},
		},
		{
			input: GatewayTags{Enabled: true, Tags: []string{}},
			want:  GatewayTags{Enabled: true, Tags: []string{}},
		},
		{
			input: GatewayTags{Enabled: true, Tags: []string{"test"}},
			want:  GatewayTags{Enabled: true, Tags: []string{"test"}},
		},
		{
			input: GatewayTags{Enabled: true, Tags: []string{"t1", "t2"}},
			want:  GatewayTags{Enabled: true, Tags: []string{"t1", "t2"}},
		},
		{
			input: GatewayTags{Enabled: false, Tags: []string{"t1", "t2"}},
			want:  GatewayTags{Enabled: false, Tags: []string{"t1", "t2"}},
		},
	}

	t.Run("Fill GatewayTags from APIDef", func(t *testing.T) {
		t.Parallel()

		for idx, tc := range testcases {
			var api apidef.APIDefinition
			tc.input.ExtractTo(&api)

			got := new(GatewayTags)
			got.Fill(api)

			assert.Equal(t, tc.want, *got, fmt.Sprintf("Test case %d", idx))
		}
	})

	t.Run("Fill OAS GatewayTags from APIDef", func(t *testing.T) {
		t.Parallel()

		for idx, tc := range testcases {
			var api apidef.APIDefinition
			tc.input.ExtractTo(&api)

			var oas OAS
			oas.Fill(api)

			var schema = oas.GetTykExtension()
			var got = schema.Server.GatewayTags

			if tc.omit {
				assert.Nil(t, got, idx)
			} else {
				assert.Equal(t, tc.want, *got, fmt.Sprintf("Test case %d", idx))
			}
		}
	})
}

func TestClientCertificates(t *testing.T) {
	t.Parallel()

	var emptyClientCertificates ClientCertificates

	var convertedAPI apidef.APIDefinition
	emptyClientCertificates.ExtractTo(&convertedAPI)

	var resultClientCertificates ClientCertificates
	resultClientCertificates.Fill(convertedAPI)

	assert.Equal(t, emptyClientCertificates, resultClientCertificates)
}

func TestCustomDomain(t *testing.T) {
	certs := []string{"c1", "c2"}
	t.Run("extractTo api definition", func(t *testing.T) {
		testcases := []struct {
			title       string
			input       Domain
			expectValue apidef.APIDefinition
		}{
			{
				"enabled=false, name=nil",
				Domain{Enabled: false, Name: ""},
				apidef.APIDefinition{DomainDisabled: true},
			},
			{
				"enabled=false, vali",
				Domain{Enabled: false, Name: "example.com", Certificates: certs},
				apidef.APIDefinition{DomainDisabled: true, Domain: "example.com", Certificates: certs},
			},
			{
				"enabled=true, name=nil",
				Domain{Enabled: true, Name: ""},
				apidef.APIDefinition{DomainDisabled: false, Domain: ""},
			},
			{
				"enabled=true, valid",
				Domain{Enabled: true, Name: "example.com", Certificates: certs},
				apidef.APIDefinition{DomainDisabled: false, Domain: "example.com", Certificates: certs},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.title, func(t *testing.T) {
				var apiDef apidef.APIDefinition
				tc.input.ExtractTo(&apiDef)

				assert.Equalf(t, tc.expectValue, apiDef, tc.title)
			})
		}
	})
	t.Run("fillFrom api definition", func(t *testing.T) {
		testcases := []struct {
			title         string
			input         apidef.APIDefinition
			expectedValue Domain
		}{
			{
				"disabled=false, name=nil",
				apidef.APIDefinition{DomainDisabled: false, Domain: ""},
				Domain{Enabled: true},
			},
			{
				"disabled=false, valid",
				apidef.APIDefinition{DomainDisabled: false, Domain: "example.com", Certificates: certs},
				Domain{Enabled: true, Name: "example.com", Certificates: certs},
			},
			{
				"disabled=true, name=nil",
				apidef.APIDefinition{DomainDisabled: true, Domain: ""},
				Domain{Enabled: false, Name: ""},
			},
			{
				"disabled=true, valid",
				apidef.APIDefinition{DomainDisabled: true, Domain: "example.com", Certificates: certs},
				Domain{Enabled: false, Name: "example.com", Certificates: certs},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.title, func(t *testing.T) {
				var customDomain Domain

				customDomain.Fill(tc.input)

				assert.Equal(t, tc.expectedValue, customDomain)
			})
		}
	})
}

func TestTagsExportServer(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		title    string
		input    apidef.APIDefinition
		expected *GatewayTags
	}{
		{
			"export segment tags if enabled",
			apidef.APIDefinition{
				TagsDisabled: false,
				Tags:         []string{"a", "b", "c"},
			},
			&GatewayTags{
				Enabled: true,
				Tags:    []string{"a", "b", "c"},
			},
		},
		{
			"export segment tags if disabled",
			apidef.APIDefinition{
				TagsDisabled: true,
				Tags:         []string{"a", "b", "c"},
			},
			&GatewayTags{
				Enabled: false,
				Tags:    []string{"a", "b", "c"},
			},
		},
		{
			"empty segment tags",
			apidef.APIDefinition{},
			&GatewayTags{
				Enabled: true,
				Tags:    nil,
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()

			server := new(Server)
			server.Fill(tc.input)

			assert.Equal(t, tc.expected, server.GatewayTags)
		})
	}
}

func TestFillDetailedTracing(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		title    string
		input    apidef.APIDefinition
		expected *DetailedTracing
	}{
		{
			"enabled",
			apidef.APIDefinition{DetailedTracing: true},
			&DetailedTracing{Enabled: true},
		},
		{
			"disabled",
			apidef.APIDefinition{DetailedTracing: false},
			nil,
		},
	}

	for _, tc := range testcases {
		tc := tc // Creating a new 'tc' scoped to the loop
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()

			server := new(Server)
			server.Fill(tc.input)

			assert.Equal(t, tc.expected, server.DetailedTracing)
		})
	}
}

func TestExportDetailedTracing(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		title    string
		input    *DetailedTracing
		expected bool
	}{
		{
			"enabled",
			&DetailedTracing{Enabled: true},
			true,
		},
		{
			"disabled",
			nil,
			false,
		},
	}

	for _, tc := range testcases {
		tc := tc // Creating a new 'tc' scoped to the loop
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()

			server := new(Server)
			server.DetailedTracing = tc.input

			var apiDef apidef.APIDefinition
			server.ExtractTo(&apiDef)

			assert.Equal(t, tc.expected, apiDef.DetailedTracing)
		})
	}
}

func TestEvents(t *testing.T) {
	t.Parallel()

	t.Run("extractTo", func(t *testing.T) {
		testcases := []struct {
			title    string
			input    Events
			expected apidef.EventHandlerMetaConfig
		}{
			{
				title: "webhook",
				input: Events{
					{
						Enabled: true,
						Type:    tykevent.QuotaExceeded,
						Action:  tykevent.WebhookAction,
						ID:      "random-id",
						WebhookCore: WebhookCore{
							Name:         "test-webhook",
							URL:          "https://webhook.site/uuid",
							Headers:      map[string]string{"Auth": "key"},
							BodyTemplate: "/path/to/template",
							Timeout:      20,
							Method:       http.MethodPost,
						},
					},
					{
						Enabled: false,
						Type:    tykevent.RateLimitExceeded,
						Action:  tykevent.WebhookAction,
						ID:      "random-id",
						WebhookCore: WebhookCore{
							Name:         "test-webhook",
							URL:          "https://webhook.site/uuid",
							Headers:      map[string]string{"Auth": "key"},
							BodyTemplate: "/path/to/template",
							Timeout:      20,
							Method:       http.MethodPost,
						},
					},
				},
				expected: apidef.EventHandlerMetaConfig{
					Events: map[tykevent.Event][]apidef.EventHandlerTriggerConfig{
						tykevent.QuotaExceeded: {
							{
								Handler: tykevent.WebHookHandler,
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
						tykevent.RateLimitExceeded: {
							{
								Handler: tykevent.WebHookHandler,
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
				input: Events{
					{
						Enabled: true,
						Type:    tykevent.QuotaExceeded,
						Action:  tykevent.Action("invalid-action"),
						ID:      "random-id",
						WebhookCore: WebhookCore{
							Name:         "test-webhook",
							URL:          "https://webhook.site/uuid",
							Headers:      map[string]string{"Auth": "key"},
							BodyTemplate: "/path/to/template",
							Timeout:      20,
							Method:       http.MethodPost,
						},
					},
				},
				expected: apidef.EventHandlerMetaConfig{},
			},
		}

		for _, tc := range testcases {
			tc := tc
			t.Run(tc.title, func(t *testing.T) {
				t.Parallel()

				server := new(Server)
				server.Events = tc.input

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
			expected Events
		}{
			{
				title: "webhook",
				input: apidef.EventHandlerMetaConfig{
					Events: map[tykevent.Event][]apidef.EventHandlerTriggerConfig{
						tykevent.QuotaExceeded: {
							{
								Handler: tykevent.WebHookHandler,
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
						tykevent.RateLimitExceeded: {
							{
								Handler: tykevent.WebHookHandler,
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
				expected: Events{
					{
						Enabled: true,
						Type:    tykevent.QuotaExceeded,
						Action:  tykevent.WebhookAction,
						ID:      "random-id",
						WebhookCore: WebhookCore{
							Name:         "test-webhook",
							URL:          "https://webhook.site/uuid",
							Headers:      map[string]string{"Auth": "key"},
							BodyTemplate: "/path/to/template",
							Timeout:      20,
							Method:       http.MethodPost,
						},
					},
					{
						Enabled: false,
						Type:    tykevent.RateLimitExceeded,
						Action:  tykevent.WebhookAction,
						ID:      "random-id",
						WebhookCore: WebhookCore{
							Name:         "test-webhook",
							URL:          "https://webhook.site/uuid",
							Headers:      map[string]string{"Auth": "key"},
							BodyTemplate: "/path/to/template",
							Timeout:      20,
							Method:       http.MethodPost,
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
				server.Events.Fill(api)

				assert.EqualValues(t, tc.expected, server.Events)
			})
		}
	})
}
