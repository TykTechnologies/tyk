package oas

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

// Verifies: SYS-REQ-104, SW-REQ-090
// SW-REQ-090:nominal:nominal
// SW-REQ-090:boundary:nominal
// SW-REQ-090:error_handling:nominal
// SW-REQ-090:error_handling:negative
// SW-REQ-090:determinism:nominal
func TestOASRootDocumentHelpersPreserveSupportBehavior(t *testing.T) {
	t.Run("extension lifecycle marshal clone and initialization remain deterministic", func(t *testing.T) {
		oasDoc := &OAS{}
		tykExtension := &XTykAPIGateway{
			Info: Info{Name: "inventory"},
			Middleware: &Middleware{Operations: Operations{
				"getInventory": &Operation{},
			}},
		}
		streamingExtension := &XTykStreaming{Streams: map[string]interface{}{"orders": map[string]interface{}{"enabled": true}}}

		oasDoc.SetTykExtension(tykExtension)
		oasDoc.SetTykStreamingExtension(streamingExtension)

		assert.Same(t, tykExtension, oasDoc.GetTykExtension())
		assert.Same(t, streamingExtension, oasDoc.GetTykStreamingExtension())
		assert.Same(t, tykExtension.Middleware, oasDoc.GetTykMiddleware())
		assert.Equal(t, tykExtension.Middleware.Operations, oasDoc.getTykOperations())

		marshaled, err := oasDoc.MarshalJSON()
		require.NoError(t, err)
		assert.Contains(t, string(marshaled), ExtensionTykAPIGateway)
		assert.Contains(t, string(marshaled), ExtensionTykStreaming)

		cloned, err := oasDoc.Clone()
		require.NoError(t, err)
		require.Equal(t, oasDoc, cloned)
		cloned.GetTykExtension().Info.Name = "inventory-copy"
		assert.Equal(t, "inventory", oasDoc.GetTykExtension().Info.Name)
		assert.Equal(t, "inventory-copy", cloned.GetTykExtension().Info.Name)

		rawGateway := json.RawMessage(`{"info":{"name":"raw-inventory"}}`)
		rawStreaming := json.RawMessage(`{"streams":{"payments":{"enabled":true}}}`)
		oasDoc.Extensions = map[string]interface{}{
			ExtensionTykAPIGateway: rawGateway,
			ExtensionTykStreaming:  rawStreaming,
		}
		assert.Equal(t, "raw-inventory", oasDoc.GetTykExtension().Info.Name)
		assert.Contains(t, oasDoc.GetTykStreamingExtension().Streams, "payments")

		oasDoc.Initialize()
		oasDoc.RemoveTykExtension()
		oasDoc.RemoveTykStreamingExtension()
		assert.Nil(t, oasDoc.GetTykExtension())
		assert.Nil(t, oasDoc.GetTykStreamingExtension())
	})

	t.Run("authentication security and middleware accessors cache typed helpers", func(t *testing.T) {
		oasDoc := &OAS{
			T: openapi3.T{
				Components: &openapi3.Components{
					SecuritySchemes: openapi3.SecuritySchemes{
						"token": &openapi3.SecuritySchemeRef{Value: &openapi3.SecurityScheme{Type: typeAPIKey}},
						"jwt":   &openapi3.SecuritySchemeRef{Value: &openapi3.SecurityScheme{Type: typeHTTP, Scheme: schemeBearer, BearerFormat: bearerFormatJWT}},
						"basic": &openapi3.SecuritySchemeRef{Value: &openapi3.SecurityScheme{Type: typeHTTP, Scheme: schemeBasic}},
						"oauth": &openapi3.SecuritySchemeRef{Value: &openapi3.SecurityScheme{Type: typeOAuth2}},
						"external": &openapi3.SecuritySchemeRef{Value: &openapi3.SecurityScheme{
							Type: typeOAuth2,
						}},
					},
				},
			},
		}
		oasDoc.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecuritySchemes: SecuritySchemes{
						"token": map[string]interface{}{"enabled": true},
						"jwt":   map[string]interface{}{"enabled": true, "source": "jwks"},
						"basic": map[string]interface{}{"enabled": true},
						"oauth": map[string]interface{}{"enabled": true},
						"external": map[string]interface{}{
							"enabled":   true,
							"providers": []interface{}{map[string]interface{}{"issuer": "https://issuer.example"}},
						},
					},
				},
			},
			Middleware: &Middleware{Operations: Operations{"listPets": &Operation{}}},
		})

		require.NotNil(t, oasDoc.getTykAuthentication())
		require.Contains(t, oasDoc.getTykSecuritySchemes(), "token")
		assert.Nil(t, oasDoc.getTykSecurityScheme("missing"))

		oasDoc.Initialize()

		token := oasDoc.getTykTokenAuth("token")
		require.NotNil(t, token)
		require.NotNil(t, token.Enabled)
		assert.True(t, *token.Enabled)
		assert.IsType(t, &Token{}, oasDoc.getTykSecuritySchemes()["token"])
		assert.IsType(t, &JWT{}, oasDoc.getTykSecuritySchemes()["jwt"])
		assert.IsType(t, &Basic{}, oasDoc.getTykSecuritySchemes()["basic"])
		assert.IsType(t, &OAuth{}, oasDoc.getTykSecuritySchemes()["oauth"])
		assert.IsType(t, &ExternalOAuth{}, oasDoc.getTykSecuritySchemes()["external"])
		assert.Contains(t, oasDoc.getTykOperations(), "listPets")
	})

	t.Run("server list helpers add remove update and replace local server shapes", func(t *testing.T) {
		tests := []struct {
			name     string
			initial  openapi3.Servers
			apply    func(*OAS) error
			expected []string
			wantErr  bool
		}{
			{
				name: "add normalizes regex variables and preserves user servers",
				initial: openapi3.Servers{
					{URL: "https://upstream.example/api"},
				},
				apply: func(oasDoc *OAS) error {
					return oasDoc.AddServers("https://{tenant:[a-z]+}.example.com/{version:v[0-9]+}")
				},
				expected: []string{"https://{tenant}.example.com/{version}", "https://upstream.example/api"},
			},
			{
				name: "remove matches normalized regex variables",
				initial: openapi3.Servers{
					{URL: "https://{tenant}.example.com/{version}"},
					{URL: "https://upstream.example/api"},
				},
				apply: func(oasDoc *OAS) error {
					return oasDoc.RemoveServer("https://{tenant:[a-z]+}.example.com/{version:v[0-9]+}")
				},
				expected: []string{"https://upstream.example/api"},
			},
			{
				name: "update replaces only first tyk-owned server",
				initial: openapi3.Servers{
					{URL: "https://old.example/api"},
					{URL: "https://user.example/api"},
				},
				apply: func(oasDoc *OAS) error {
					oasDoc.UpdateServers("https://new.example/api", "https://old.example/api")
					return nil
				},
				expected: []string{"https://new.example/api", "https://user.example/api"},
			},
			{
				name: "replace prepends new tyk servers and keeps user servers",
				initial: openapi3.Servers{
					{URL: "https://old-a.example/api"},
					{URL: "https://user.example/api"},
				},
				apply: func(oasDoc *OAS) error {
					oasDoc.ReplaceServers([]string{"https://new-a.example/api", "https://new-b.example/api"}, []string{"https://old-a.example/api"})
					return nil
				},
				expected: []string{"https://new-a.example/api", "https://new-b.example/api", "https://user.example/api"},
			},
			{
				name: "invalid server regex returns an error without mutating servers",
				initial: openapi3.Servers{
					{URL: "https://upstream.example/api"},
				},
				apply: func(oasDoc *OAS) error {
					return oasDoc.AddServers("https://{tenant:[a-z]+}.example.com/{version:[0-9]+}}")
				},
				expected: []string{"https://upstream.example/api"},
				wantErr:  true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				oasDoc := &OAS{T: openapi3.T{Servers: tt.initial}}
				err := tt.apply(oasDoc)
				if tt.wantErr {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}

				var urls []string
				for _, server := range oasDoc.Servers {
					urls = append(urls, server.URL)
				}
				assert.Equal(t, tt.expected, urls)
			})
		}
	})

	t.Run("validation defaults and classic compatibility helpers stay locally scoped", func(t *testing.T) {
		oasDoc := &OAS{T: openapi3.T{
			OpenAPI: "3.0.3",
			Info:    &openapi3.Info{Title: "inventory", Version: "v1"},
			Paths:   openapi3.NewPaths(),
			Security: openapi3.SecurityRequirements{
				openapi3.SecurityRequirement{"missing": []string{}},
			},
			Components: &openapi3.Components{SecuritySchemes: openapi3.SecuritySchemes{}},
		}}
		err := oasDoc.Validate(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "No components or security schemes present in OAS")

		oasDoc.setRequiredFields("inventory", "v2")
		assert.Equal(t, DefaultOpenAPI, oasDoc.OpenAPI)
		assert.Equal(t, "inventory", oasDoc.Info.Title)
		assert.Equal(t, "v2", oasDoc.Info.Version)

		api := &apidef.APIDefinition{VersionData: apidef.VersionData{Versions: map[string]apidef.VersionInfo{
			Main: {
				ExtendedPaths: apidef.ExtendedPathsSet{
					ValidateJSON: []apidef.ValidatePathMeta{{Path: "/pets", Method: "POST"}},
				},
			},
			"v2": {
				ExtendedPaths: apidef.ExtendedPathsSet{
					ValidateJSON: []apidef.ValidatePathMeta{{Path: "/pets", Method: "POST"}},
				},
			},
		}}}
		clearClassicAPIForSomeFeatures(api)
		assert.Nil(t, api.VersionData.Versions[Main].ExtendedPaths.ValidateJSON)
		assert.Len(t, api.VersionData.Versions["v2"].ExtendedPaths.ValidateJSON, 1)

		optionCases := []struct {
			name     string
			config   config.OASConfig
			expected int
		}{
			{name: "both disabled", config: config.OASConfig{}, expected: 2},
			{name: "schema defaults enabled", config: config.OASConfig{ValidateSchemaDefaults: true}, expected: 1},
			{name: "examples enabled", config: config.OASConfig{ValidateExamples: true}, expected: 1},
			{name: "both enabled", config: config.OASConfig{ValidateSchemaDefaults: true, ValidateExamples: true}, expected: 0},
		}
		for _, tt := range optionCases {
			t.Run(tt.name, func(t *testing.T) {
				assert.Len(t, GetValidationOptionsFromConfig(tt.config), tt.expected)
			})
		}
	})
}
