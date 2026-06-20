package schema

import (
	"errors"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/header"
)

// Verifies: SYS-REQ-104, SW-REQ-044
// SW-REQ-044:nominal:nominal
func TestNewVisitor(t *testing.T) {
	visitor := NewVisitor()

	assert.NotNil(t, visitor)
	assert.NotNil(t, visitor.manipulations)
	assert.NotNil(t, visitor.visited)
	assert.Empty(t, visitor.manipulations)
	assert.Empty(t, visitor.visited)
}

// Verifies: SYS-REQ-104, SW-REQ-044
// SW-REQ-044:nominal:nominal
func TestVisitor_AddManipulation(t *testing.T) {
	visitor := NewVisitor()

	visitor.AddSchemaManipulation(func(schema *openapi3.Schema) {
		schema.Description = "test"
	})

	assert.Len(t, visitor.manipulations, 1)
}

// Verifies: SYS-REQ-104, SW-REQ-044
// SW-REQ-044:nominal:nominal
// SW-REQ-044:determinism:nominal
func TestVisitor_applyManipulations(t *testing.T) {
	visitor := NewVisitor()

	calledDesc, calledTitle := false, false
	schemaDesc := "custom description"
	schemaTitle := "custom title"

	visitor.AddSchemaManipulation(func(schema *openapi3.Schema) {
		calledDesc = true
		schema.Description = schemaDesc
	})
	visitor.AddSchemaManipulation(func(schema *openapi3.Schema) {
		calledTitle = true
		schema.Title = schemaTitle
	})

	schema := openapi3.NewSchema()
	visitor.applyManipulations(schema)

	assert.True(t, calledDesc)
	assert.True(t, calledTitle)
	assert.Equal(t, schemaDesc, schema.Description)
	assert.Equal(t, schemaTitle, schema.Title)
}

// Verifies: SYS-REQ-104, SW-REQ-044
// SW-REQ-044:boundary:nominal
// SW-REQ-044:boundary:boundary
// SW-REQ-044:idempotency:nominal
func TestVisitor_isVisited_and_resetVisited(t *testing.T) {
	visitor := NewVisitor()
	schema := openapi3.NewSchema()

	assert.False(t, visitor.isVisited(schema))
	assert.True(t, visitor.isVisited(schema))

	visitor.resetVisited()

	assert.False(t, visitor.isVisited(schema))
}

// Verifies: SYS-REQ-104, SW-REQ-044
// SW-REQ-044:nominal:nominal
func TestVisitor_ProcessOAS_Components(t *testing.T) {
	schema1 := openapi3.NewSchema()
	schema2 := openapi3.NewSchema()

	doc := &oas.OAS{
		T: openapi3.T{
			Components: &openapi3.Components{
				Schemas: openapi3.Schemas{
					"Schema1": openapi3.NewSchemaRef("", schema1),
					"Schema2": openapi3.NewSchemaRef("", schema2),
				},
			},
		},
	}

	visitor := NewVisitor()

	visitCount := 0
	schemaDesc := "visited"
	visitor.AddSchemaManipulation(func(schema *openapi3.Schema) {
		visitCount++
		schema.Description = schemaDesc
	})

	visitor.ProcessOAS(doc)

	assert.Equal(t, 2, visitCount)
	assert.Equal(t, schemaDesc, schema1.Description)
	assert.Equal(t, schemaDesc, schema2.Description)
}

// Verifies: SYS-REQ-104, SW-REQ-044
// SW-REQ-044:nominal:nominal
// SW-REQ-044:boundary:nominal
// SW-REQ-044:boundary:boundary
func TestVisitor_ProcessOAS_Paths(t *testing.T) {
	paramSchema := openapi3.NewSchema()
	reqBodySchema := openapi3.NewSchema()
	respSchema := openapi3.NewSchema()
	headerSchema := openapi3.NewSchema()
	callbackSchema := openapi3.NewSchema()

	callback := openapi3.NewCallback()
	callback.Set("/callback", &openapi3.PathItem{
		Post: &openapi3.Operation{
			RequestBody: &openapi3.RequestBodyRef{
				Value: &openapi3.RequestBody{
					Content: openapi3.Content{
						header.ApplicationJSON: &openapi3.MediaType{
							Schema: openapi3.NewSchemaRef("", callbackSchema),
						},
					},
				},
			},
		},
	})

	pathItem := &openapi3.PathItem{
		Get: &openapi3.Operation{
			Parameters: openapi3.Parameters{
				&openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Schema: openapi3.NewSchemaRef("", paramSchema),
					},
				},
			},
			RequestBody: &openapi3.RequestBodyRef{
				Value: &openapi3.RequestBody{
					Content: openapi3.Content{
						header.ApplicationJSON: &openapi3.MediaType{
							Schema: openapi3.NewSchemaRef("", reqBodySchema),
						},
					},
				},
			},
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{Value: &openapi3.Response{
					Content: openapi3.Content{
						header.ApplicationJSON: &openapi3.MediaType{
							Schema: openapi3.NewSchemaRef("", respSchema),
						},
					},
					Headers: openapi3.Headers{
						"X-Test": &openapi3.HeaderRef{
							Value: &openapi3.Header{
								Parameter: openapi3.Parameter{
									Schema: openapi3.NewSchemaRef("", headerSchema),
								},
							},
						},
					},
				},
				}),
			),
			Callbacks: openapi3.Callbacks{
				"onEvent": &openapi3.CallbackRef{Value: callback},
			},
		},
	}

	paths := openapi3.NewPaths()
	paths.Set("/test", pathItem)
	paths.Set("/nil", nil)

	doc := &oas.OAS{
		T: openapi3.T{
			Paths: paths,
		},
	}

	visitor := NewVisitor()

	visitCount := 0
	schemaDesc := "visited"
	visitor.AddSchemaManipulation(func(schema *openapi3.Schema) {
		visitCount++
		schema.Description = schemaDesc
	})

	visitor.ProcessOAS(doc)

	assert.Equal(t, 5, visitCount)
	assert.Equal(t, schemaDesc, paramSchema.Description)
	assert.Equal(t, schemaDesc, reqBodySchema.Description)
	assert.Equal(t, schemaDesc, respSchema.Description)
	assert.Equal(t, schemaDesc, headerSchema.Description)
	assert.Equal(t, schemaDesc, callbackSchema.Description)
}

// Verifies: SYS-REQ-104, SW-REQ-044
// SW-REQ-044:nominal:nominal
// SW-REQ-044:boundary:nominal
// SW-REQ-044:boundary:boundary
// SW-REQ-044:nil_safety:nominal
// SW-REQ-044:nil_safety:negative
func TestVisitor_processSchema(t *testing.T) {
	rootSchema := openapi3.NewSchema()
	propSchema := openapi3.NewSchema()
	itemSchema := openapi3.NewSchema()
	addPropSchema := openapi3.NewSchema()
	notSchema := openapi3.NewSchema()
	allOfSchema := openapi3.NewSchema()
	anyOfSchema := openapi3.NewSchema()
	oneOfSchema := openapi3.NewSchema()
	schemaA := openapi3.NewSchema()
	schemaB := openapi3.NewSchema()

	visitor := NewVisitor()
	visitCount := 0

	visitor.AddSchemaManipulation(func(_ *openapi3.Schema) {
		visitCount++
	})

	t.Run("Recursion", func(t *testing.T) {
		rootSchema.Properties = openapi3.Schemas{
			"prop1": openapi3.NewSchemaRef("", propSchema),
		}
		rootSchema.Items = openapi3.NewSchemaRef("", itemSchema)
		rootSchema.AdditionalProperties.Schema = openapi3.NewSchemaRef("", addPropSchema)
		rootSchema.Not = openapi3.NewSchemaRef("", notSchema)
		rootSchema.AllOf = openapi3.SchemaRefs{openapi3.NewSchemaRef("", allOfSchema)}
		rootSchema.AnyOf = openapi3.SchemaRefs{openapi3.NewSchemaRef("", anyOfSchema)}
		rootSchema.OneOf = openapi3.SchemaRefs{openapi3.NewSchemaRef("", oneOfSchema)}

		visitCount = 0
		visitor.ProcessSchema(openapi3.NewSchemaRef("", rootSchema))

		// root + 7 sub-schemas = 8
		assert.Equal(t, 8, visitCount)
	})

	t.Run("CircularReference", func(t *testing.T) {
		// A has property B
		schemaA.Properties = openapi3.Schemas{
			"b": openapi3.NewSchemaRef("", schemaB),
		}

		// B has property A (circular reference)
		schemaB.Properties = openapi3.Schemas{
			"a": openapi3.NewSchemaRef("", schemaA),
		}

		visitCount = 0
		visitor.ProcessSchema(openapi3.NewSchemaRef("", schemaA))

		// Should visit A, then B, then stop at A because it's already visited
		assert.Equal(t, 2, visitCount)
	})

	t.Run("Nil", func(t *testing.T) {
		assert.NotPanics(t, func() {
			visitor.ProcessSchema(nil)
			visitor.ProcessSchema(&openapi3.SchemaRef{Value: nil})
		})
	})
}

// Verifies: SYS-REQ-104, SW-REQ-044
// SW-REQ-044:encoding_safety:nominal
// SW-REQ-044:boundary:nominal
// SW-REQ-044:boundary:boundary
func TestVisitor_regexpManipulations(t *testing.T) {
	tcTransformUnicodeEscapesToRE2 := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Pattern with unicode range",
			input:    "{\"^[\\\\u0000-\\\\u017f]*$\"}",
			expected: "{\"^[\\\\x{0000}-\\\\x{017f}]*$\"}",
		},
		{
			name:     "Null character",
			input:    "{\"\\\\u0000\"}",
			expected: "{\"\\\\x{0000}\"}",
		},
		{
			name:     "Multiple unicode characters",
			input:    "{\"\\\\u0041\\\\u0042\\\\u0043\"}",
			expected: "{\"\\\\x{0041}\\\\x{0042}\\\\x{0043}\"}",
		},
		{
			name:     "No unicode characters",
			input:    "{\"^[a-zA-Z0-9]*$\"}",
			expected: "{\"^[a-zA-Z0-9]*$\"}",
		},
		{
			name:     "Empty input",
			input:    ``,
			expected: ``,
		},
		{
			name:     "Mixed content",
			input:    "{\"A string with \\\\u0020 space\"}",
			expected: "{\"A string with \\\\x{0020} space\"}",
		},
		{
			name:     "Already contains RE2 escapes",
			input:    "\"\\\\x{1234}\"",
			expected: "\"\\\\x{1234}\"",
		},
	}

	tcRestoreUnicodeEscapesFromRE2 := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Pattern with RE2 range",
			input:    "{\"^[\\\\x{0000}-\\\\x{017f}]*$\"}",
			expected: "{\"^[\\\\u0000-\\\\u017f]*$\"}",
		},
		{
			name:     "Null character escape",
			input:    "{\"\\\\x{0000}\"}",
			expected: "{\"\\\\u0000\"}",
		},
		{
			name:     "Multiple RE2 escapes",
			input:    "{\"\\\\x{0041}\\\\x{0042}\\\\x{0043}\"}",
			expected: "{\"\\\\u0041\\\\u0042\\\\u0043\"}",
		},
		{
			name:     "No RE2 escapes",
			input:    "{\"^[a-zA-Z0-9]*$\"}",
			expected: "{\"^[a-zA-Z0-9]*$\"}",
		},
		{
			name:     "Empty input",
			input:    ``,
			expected: ``,
		},
		{
			name:     "Mixed content",
			input:    "{{\"description\": \"A string with \\\\x{0020} space\"}}",
			expected: "{{\"description\": \"A string with \\\\u0020 space\"}}",
		},
		{
			name:     "Already contains unicode escapes",
			input:    "{\"\\\\u1234\"}",
			expected: "{\"\\\\u1234\"}",
		},
	}

	schemaName := "testSchema"
	testOAS := &oas.OAS{T: openapi3.T{}}

	testOAS.Components = &openapi3.Components{
		Schemas: openapi3.Schemas{
			schemaName: {
				Value: openapi3.NewSchema(),
			},
		},
	}

	visitor := NewVisitor()

	t.Run("TransformUnicodeEscapesToRE2", func(t *testing.T) {
		resetVisitor(visitor)
		visitor.AddSchemaManipulation(TransformUnicodeEscapesToRE2Manipulation)

		for _, tc := range tcTransformUnicodeEscapesToRE2 {
			t.Run(tc.name, func(t *testing.T) {
				visitor.resetVisited()

				testOAS.Components.Schemas[schemaName].Value.Pattern = tc.input
				visitor.ProcessOAS(testOAS)

				assert.Equal(t, tc.expected, testOAS.Components.Schemas[schemaName].Value.Pattern)
			})
		}
	})

	t.Run("RestoreUnicodeEscapesFromRE2", func(t *testing.T) {
		resetVisitor(visitor)
		visitor.AddSchemaManipulation(RestoreUnicodeEscapesFromRE2Manipulation)

		for _, tc := range tcRestoreUnicodeEscapesFromRE2 {
			t.Run(tc.name, func(t *testing.T) {
				visitor.resetVisited()

				testOAS.Components.Schemas[schemaName].Value.Pattern = tc.input
				visitor.ProcessOAS(testOAS)

				assert.Equal(t, tc.expected, testOAS.Components.Schemas[schemaName].Value.Pattern)
			})
		}
	})
}

// Verifies: SYS-REQ-104, SW-REQ-044
// SW-REQ-044:encoding_safety:nominal
// SW-REQ-044:error_handling:nominal
// SW-REQ-044:error_handling:negative
// SW-REQ-044:nil_safety:nominal
// SW-REQ-044:nil_safety:negative
func TestRestoreUnicodeEscapesInError(t *testing.T) {
	assert.NoError(t, RestoreUnicodeEscapesInError(nil))

	err := RestoreUnicodeEscapesInError(errors.New("pattern uses \\x{0041}"))

	assert.EqualError(t, err, "pattern uses \\u0041")
}

func resetVisitor(visitor *Visitor) {
	visitor.resetVisited()
	visitor.manipulations = Manipulations{}
}
