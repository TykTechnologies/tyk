package apidef

import (
	"testing"

	schema "github.com/xeipuuv/gojsonschema"
)

func TestSchema(t *testing.T) {
	schemaLoader := schema.NewBytesLoader([]byte(Schema))

	spec := DummyAPI()
	goLoader := schema.NewGoLoader(spec)
	result, err := schema.Validate(schemaLoader, goLoader)
	if err != nil {
		t.Error(err)
	}

	if !result.Valid() {
		for _, err := range result.Errors() {
			t.Error(err)
		}
	}
}

func TestSchemaGraphqlConfig(t *testing.T) {
	schemaLoader := schema.NewBytesLoader([]byte(Schema))

	spec := DummyAPI()
	spec.GraphQL.ExecutionMode = ""

	goLoader := schema.NewGoLoader(spec)

	result, err := schema.Validate(schemaLoader, goLoader)
	if err != nil {
		t.Error(err)
	}

	if !result.Valid() {
		for _, err := range result.Errors() {
			t.Error(err)
		}
	}
}
