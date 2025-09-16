package oas

import (
	"fmt"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSecurityRequirementsPreservation(t *testing.T) {
	testCases := []struct {
		name            string
		inputSecurity   openapi3.SecurityRequirements
		mode            string
		expectPreserved bool
	}{
		{
			name: "Two separate OR requirements (user's bug case)",
			inputSecurity: openapi3.SecurityRequirements{
				{"authToken": []string{}},
				{"basicAuth": []string{}},
			},
			mode:            "legacy",
			expectPreserved: true,
		},
		{
			name: "Single requirement with one scheme",
			inputSecurity: openapi3.SecurityRequirements{
				{"authToken": []string{}},
			},
			mode:            "legacy",
			expectPreserved: true,
		},
		{
			name: "AND requirements (multiple in one)",
			inputSecurity: openapi3.SecurityRequirements{
				{"authToken": []string{}, "basicAuth": []string{}},
			},
			mode:            "legacy",
			expectPreserved: true,
		},
		{
			name: "Three separate OR requirements",
			inputSecurity: openapi3.SecurityRequirements{
				{"apiKey": []string{}},
				{"oauth2": []string{"read", "write"}},
				{"jwt": []string{}},
			},
			mode:            "compliant",
			expectPreserved: true,
		},
		{
			name: "Mixed AND/OR requirements",
			inputSecurity: openapi3.SecurityRequirements{
				{"apiKey": []string{}},
				{"oauth2": []string{"read"}, "jwt": []string{}},
			},
			mode:            "legacy",
			expectPreserved: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fmt.Printf("\n=== Testing: %s ===\n", tc.name)

			// Create OAS with the given security requirements
			oasDoc := &openapi3.T{
				OpenAPI: "3.0.3",
				Info: &openapi3.Info{
					Title:   "Security Test",
					Version: "1.0.0",
				},
				Servers: openapi3.Servers{
					&openapi3.Server{URL: "http://localhost:8181/test/"},
				},
				Security: tc.inputSecurity,
				Paths:    openapi3.NewPaths(),
				Components: &openapi3.Components{
					SecuritySchemes: createTestSecuritySchemes(),
				},
			}

			oasWrapper := &OAS{T: *oasDoc}
			tykExt := createTestTykExtension()
			oasWrapper.SetTykExtension(tykExt)

			fmt.Println("Input Security:")
			for i, req := range tc.inputSecurity {
				fmt.Printf("  [%d]: %v\n", i, req)
			}

			// Extract to APIDefinition
			apiDef := &apidef.APIDefinition{}
			apiDef.SecurityProcessingMode = tc.mode
			oasWrapper.ExtractTo(apiDef)

			fmt.Printf("Extracted SecurityRequirements: %v\n", apiDef.SecurityRequirements)

			// Fill back to new OAS
			resultOAS := &OAS{}
			resultOAS.Fill(*apiDef)

			fmt.Println("Result Security:")
			for i, req := range resultOAS.T.Security {
				fmt.Printf("  [%d]: %v\n", i, req)
			}

			// Verify preservation
			if tc.expectPreserved {
				assert.Equal(t, len(tc.inputSecurity), len(resultOAS.T.Security),
					"Number of security requirements should be preserved")

				// Check that structure is preserved
				for i, inputReq := range tc.inputSecurity {
					if i < len(resultOAS.T.Security) {
						resultReq := resultOAS.T.Security[i]
						assert.Equal(t, len(inputReq), len(resultReq),
							"Number of schemes in requirement %d should be preserved", i)

						for scheme := range inputReq {
							assert.Contains(t, resultReq, scheme,
								"Scheme %s should be in requirement %d", scheme, i)
						}
					}
				}
			}
		})
	}
}

func createTestSecuritySchemes() openapi3.SecuritySchemes {
	return openapi3.SecuritySchemes{
		"apiKey": &openapi3.SecuritySchemeRef{
			Value: &openapi3.SecurityScheme{
				Type: "apiKey",
				In:   "header",
				Name: "X-API-Key",
			},
		},
		"authToken": &openapi3.SecuritySchemeRef{
			Value: &openapi3.SecurityScheme{
				Type: "apiKey",
				In:   "header",
				Name: "Authorization",
			},
		},
		"basicAuth": &openapi3.SecuritySchemeRef{
			Value: &openapi3.SecurityScheme{
				Type:   "http",
				Scheme: "basic",
			},
		},
		"oauth2": &openapi3.SecuritySchemeRef{
			Value: &openapi3.SecurityScheme{
				Type: "oauth2",
				Flows: &openapi3.OAuthFlows{
					AuthorizationCode: &openapi3.OAuthFlow{
						AuthorizationURL: "https://example.com/oauth/authorize",
						TokenURL:         "https://example.com/oauth/token",
						Scopes: map[string]string{
							"read":  "Read access",
							"write": "Write access",
						},
					},
				},
			},
		},
		"jwt": &openapi3.SecuritySchemeRef{
			Value: &openapi3.SecurityScheme{
				Type:         "http",
				Scheme:       "bearer",
				BearerFormat: "JWT",
			},
		},
	}
}

func createTestTykExtension() *XTykAPIGateway {
	boolTrue := true
	return &XTykAPIGateway{
		Info: Info{
			Name: "test-api",
			State: State{
				Active: true,
			},
		},
		Server: Server{
			ListenPath: ListenPath{
				Value: "/test",
				Strip: true,
			},
			Authentication: &Authentication{
				Enabled: true,
				SecuritySchemes: SecuritySchemes{
					"apiKey": &Token{
						Enabled: &boolTrue,
					},
					"authToken": &Token{
						Enabled: &boolTrue,
					},
					"basicAuth": &Basic{
						Enabled: true,
					},
					"oauth2": &OAuth{
						Enabled: true,
					},
					"jwt": &JWT{
						Enabled: true,
					},
				},
			},
		},
	}
}
