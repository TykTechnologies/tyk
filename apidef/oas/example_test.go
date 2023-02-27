package oas

import (
	"context"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

func Test_exampleExtractor(t *testing.T) {
	cases := []struct {
		name        string
		schema      string
		expectedRes interface{}
	}{
		{
			"object",
			`{
				"type": "object",
				"properties": {	
				  "name": {
					"type": "string",
					"example": "bird"
				  }
				}
			}`,
			map[string]interface{}{
				"name": "bird",
			},
		},
		{
			"object without properties",
			`{
				"type": "object"
			}`,
			map[string]interface{}{},
		},
		{
			"object with example",
			`{
				"type": "object",
				"properties": {	
				  "name": {
					"type": "string",
					"example": "bird"
				  }
				},
				"example": "duck"
			}`,
			"duck",
		},
		{
			"boolean",
			`{
				"type": "boolean"
			}`,
			true,
		},
		{
			"boolean with example",
			`{
				"type": "boolean",
				"example": false	
			}`,
			false,
		},
		{
			"string",
			`{
				"type": "string"
			}`,
			"string",
		},
		{
			"string with just example",
			`{
				"type": "string",
				"example": "bird"	
			}`,
			"bird",
		},
		{
			"string with just enum",
			`{
				"type": "string",	
				"enum": ["duck", "bird"]	
			}`,
			"duck",
		},
		{
			"string with enum and example",
			`{
				"type": "string",
				"example": "bird",
				"enum": ["duck"]	
			}`,
			"bird",
		},
		{
			"integer",
			`{
				"type": "integer"
			}`,
			0,
		},
		{
			"integer with example",
			`{
				"type": "integer",
				"example": 5	
			}`, float64(5),
		},
		{
			"number",
			`{
				"type": "number"
			}`,
			0,
		},
		{
			"number with example",
			`{
				"type": "number",
				"example": 5	
			}`, float64(5),
		},
		{
			"array",
			`{
				"type": "array",
				"items": {
					"type": "string",
					"example": "bird"
				}
			}`,
			[]interface{}{"bird"},
		},
		{
			"array with example",
			`{
				"type": "array",
				"items": {
					"type": "string",
					"example": "bird"
				},
				"example": "duck"
			}`,
			"duck",
		},
	}

	for _, c := range cases {
		schemaRef := &openapi3.SchemaRef{}
		err := schemaRef.UnmarshalJSON([]byte(c.schema))
		assert.NoError(t, err)

		assert.NoError(t, schemaRef.Validate(context.Background()))

		actualRes := ExampleExtractor(schemaRef)

		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.expectedRes, actualRes)
		})
	}
}
