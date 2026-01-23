package oas

import (
	"context"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

// TestOAS_Validate_OAS31_NullType tests OAS 3.1 null type validation
// These tests will initially fail as OAS 3.1 validation is not yet fully implemented
func TestOAS_Validate_OAS31_NullType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		oasVersion    string // Allow specifying version (default: 3.1.2)
		setupOAS      func(oas *OAS)
		expectedError string // empty means should pass
	}{
		{
			name: "OAS 3.1 with null type array - should pass",
			setupOAS: func(oas *OAS) {
				schema := &openapi3.Schema{
					Type: &openapi3.Types{"object"},
					Properties: openapi3.Schemas{
						"name": &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type: &openapi3.Types{"string", "null"},
							},
						},
					},
				}
				addPostOperationWithRequestBodySchema(oas, "/users", schema)
				addMinimalTykExtension(oas)
			},
			expectedError: "",
		},
		{
			name: "OAS 3.1 with standalone null type - should pass",
			setupOAS: func(oas *OAS) {
				schema := &openapi3.Schema{
					Type: &openapi3.Types{"object"},
					Properties: openapi3.Schemas{
						"nullField": &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type: &openapi3.Types{"null"},
							},
						},
					},
				}
				addPostOperationWithRequestBodySchema(oas, "/test", schema)
				addMinimalTykExtension(oas)
			},
			expectedError: "",
		},
		{
			name:       "OAS 3.0 with nullable true - should pass (baseline)",
			oasVersion: "3.0.3",
			setupOAS: func(oas *OAS) {
				schema := &openapi3.Schema{
					Type: &openapi3.Types{"object"},
					Properties: openapi3.Schemas{
						"name": &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type:     &openapi3.Types{"string"},
								Nullable: true,
							},
						},
					},
				}
				addPostOperationWithRequestBodySchema(oas, "/users", schema)
				addMinimalTykExtension(oas)
			},
			expectedError: "",
		},
		{
			name: "OAS 3.1 response with nullable property - should pass",
			setupOAS: func(oas *OAS) {
				schema := &openapi3.Schema{
					Type: &openapi3.Types{"object"},
					Properties: openapi3.Schemas{
						"data": &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type: &openapi3.Types{"string", "null"},
							},
						},
					},
				}
				addGetOperationWithResponseSchema(oas, "/users", schema)
				addMinimalTykExtension(oas)
			},
			expectedError: "",
		},
		{
			name: "OAS 3.1 component schema with null type - should pass",
			setupOAS: func(oas *OAS) {
				// Add schema to components
				if oas.Components == nil {
					oas.Components = &openapi3.Components{}
				}
				if oas.Components.Schemas == nil {
					oas.Components.Schemas = make(openapi3.Schemas)
				}

				oas.Components.Schemas["User"] = &openapi3.SchemaRef{
					Value: &openapi3.Schema{
						Type: &openapi3.Types{"object"},
						Properties: openapi3.Schemas{
							"name": &openapi3.SchemaRef{
								Value: &openapi3.Schema{
									Type: &openapi3.Types{"string", "null"},
								},
							},
						},
					},
				}

				// Reference the component schema
				pathItem := &openapi3.PathItem{
					Post: &openapi3.Operation{
						OperationID: "createUser",
						RequestBody: &openapi3.RequestBodyRef{
							Value: &openapi3.RequestBody{
								Required: true,
								Content: openapi3.Content{
									"application/json": &openapi3.MediaType{
										Schema: &openapi3.SchemaRef{
											Ref: "#/components/schemas/User",
										},
									},
								},
							},
						},
						Responses: openapi3.NewResponses(),
					},
				}
				pathItem.Post.Responses.Set("200", &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: getStrPointer("Success"),
					},
				})
				oas.Paths.Set("/users", pathItem)
				addMinimalTykExtension(oas)
			},
			expectedError: "",
		},
		{
			name: "OAS 3.1 with mixed null and nullable - should pass with type array taking precedence",
			setupOAS: func(oas *OAS) {
				schema := &openapi3.Schema{
					Type: &openapi3.Types{"object"},
					Properties: openapi3.Schemas{
						"mixedField": &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type:     &openapi3.Types{"string", "null"}, // New syntax
								Nullable: true,                              // Deprecated syntax
							},
						},
					},
				}
				addPostOperationWithRequestBodySchema(oas, "/test", schema)
				addMinimalTykExtension(oas)
			},
			expectedError: "",
		},
		{
			name: "OAS 3.1 with multiple types including null - should pass",
			setupOAS: func(oas *OAS) {
				schema := &openapi3.Schema{
					Type: &openapi3.Types{"object"},
					Properties: openapi3.Schemas{
						"flexibleField": &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type: &openapi3.Types{"string", "number", "boolean", "null"},
							},
						},
					},
				}
				addPostOperationWithRequestBodySchema(oas, "/test", schema)
				addMinimalTykExtension(oas)
			},
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version := tt.oasVersion
			if version == "" {
				version = "3.1.2" // Default to 3.1.2
			}

			oas := createBaseOAS(version, "Test API")
			tt.setupOAS(oas)

			err := oas.Validate(context.Background())
			if tt.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			}
		})
	}
}
