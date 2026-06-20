package oas

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

// Verifies: SYS-REQ-104, SW-REQ-052
// SW-REQ-052:nominal:nominal
// SW-REQ-052:boundary:nominal
// SW-REQ-052:determinism:nominal
func TestExampleExtractorPreservesSchemaExampleShape(t *testing.T) {
	t.Run("nil schema reference returns nil", func(t *testing.T) {
		assert.Nil(t, ExampleExtractor(nil))
	})

	t.Run("explicit example wins over object properties and enum values", func(t *testing.T) {
		objectSchema := openapi3.NewObjectSchema()
		objectSchema.Example = map[string]interface{}{"kind": "explicit"}
		objectSchema.Properties["kind"] = &openapi3.SchemaRef{
			Value: stringExampleSchema("property"),
		}

		assert.Equal(t, map[string]interface{}{"kind": "explicit"}, ExampleExtractor(&openapi3.SchemaRef{Value: objectSchema}))

		enumSchema := openapi3.NewStringSchema()
		enumSchema.Enum = []interface{}{"first", "second"}
		enumSchema.Example = "chosen"
		assert.Equal(t, "chosen", ExampleExtractor(&openapi3.SchemaRef{Value: enumSchema}))
	})

	t.Run("object and array schemas recurse into child schema examples", func(t *testing.T) {
		objectSchema := openapi3.NewObjectSchema()
		objectSchema.Properties["name"] = &openapi3.SchemaRef{
			Value: stringExampleSchema("gateway"),
		}
		objectSchema.Properties["enabled"] = &openapi3.SchemaRef{
			Value: openapi3.NewBoolSchema(),
		}

		assert.Equal(t, map[string]interface{}{
			"name":    "gateway",
			"enabled": true,
		}, ExampleExtractor(&openapi3.SchemaRef{Value: objectSchema}))

		arraySchema := openapi3.NewArraySchema()
		arraySchema.Items = &openapi3.SchemaRef{
			Value: stringExampleSchema("item"),
		}
		assert.Equal(t, []interface{}{"item"}, ExampleExtractor(&openapi3.SchemaRef{Value: arraySchema}))
	})

	t.Run("enum and primitive defaults are stable", func(t *testing.T) {
		enumSchema := openapi3.NewStringSchema()
		enumSchema.Enum = []interface{}{"alpha", "beta"}
		assert.Equal(t, "alpha", ExampleExtractor(&openapi3.SchemaRef{Value: enumSchema}))

		assert.Equal(t, "string", ExampleExtractor(&openapi3.SchemaRef{Value: openapi3.NewStringSchema()}))
		assert.Equal(t, 0, ExampleExtractor(&openapi3.SchemaRef{Value: openapi3.NewIntegerSchema()}))
		assert.Equal(t, 0, ExampleExtractor(&openapi3.SchemaRef{Value: openapi3.NewFloat64Schema()}))
		assert.Equal(t, true, ExampleExtractor(&openapi3.SchemaRef{Value: openapi3.NewBoolSchema()}))
		assert.Nil(t, ExampleExtractor(&openapi3.SchemaRef{Value: &openapi3.Schema{}}))
	})

	t.Run("repeated extraction returns the same result for the same schema", func(t *testing.T) {
		schema := openapi3.NewObjectSchema()
		arraySchema := openapi3.NewArraySchema()
		arraySchema.Items = &openapi3.SchemaRef{
			Value: stringExampleSchema("entry"),
		}
		schema.Properties["items"] = &openapi3.SchemaRef{
			Value: arraySchema,
		}

		first := ExampleExtractor(&openapi3.SchemaRef{Value: schema})
		second := ExampleExtractor(&openapi3.SchemaRef{Value: schema})
		assert.Equal(t, first, second)
	})
}

func stringExampleSchema(example string) *openapi3.Schema {
	schema := openapi3.NewStringSchema()
	schema.Example = example
	return schema
}
