package oas

import "github.com/getkin/kin-openapi/openapi3"

// ExampleExtractor returns an example payload according to the openapi3.SchemaRef object.
func ExampleExtractor(schema *openapi3.SchemaRef) interface{} {
	if schema == nil {
		return nil
	}

	val := schema.Value
	if val.Example != nil {
		return val.Example
	}

	switch {
	case val.Type.Is(openapi3.TypeObject):
		obj := make(map[string]interface{})
		for name, prop := range schema.Value.Properties {
			obj[name] = ExampleExtractor(prop)
		}

		return obj
	case val.Type.Is(openapi3.TypeArray):
		items := ExampleExtractor(val.Items)
		return []interface{}{items}
	default:
		if len(val.Enum) > 0 {
			return val.Enum[0]
		}
		return emptyExampleVal(val)
	}
}

func emptyExampleVal(schema *openapi3.Schema) interface{} {
	switch {
	case schema.Type.Is(openapi3.TypeString):
		return "string"
	case schema.Type.Is(openapi3.TypeInteger), schema.Type.Is(openapi3.TypeNumber):
		return 0
	case schema.Type.Is(openapi3.TypeBoolean):
		return true
	case schema.Type.Is(openapi3.TypeArray):
		return []interface{}{}
	default:
		return nil
	}
}
