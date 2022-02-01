package graphqljsonschema

import (
	"context"
	"encoding/json"

	"github.com/buger/jsonparser"
	"github.com/qri-io/jsonschema"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
)

func FromTypeRef(operation, definition *ast.Document, typeRef int) JsonSchema {
	resolver := &fromTypeRefResolver{
		overrides: map[string]JsonSchema{},
	}
	return resolver.fromTypeRef(operation, definition, typeRef)
}

func FromTypeRefWithOverrides(operation, definition *ast.Document, typeRef int, overrides map[string]JsonSchema) JsonSchema {
	resolver := &fromTypeRefResolver{
		overrides: overrides,
	}
	return resolver.fromTypeRef(operation, definition, typeRef)
}

type fromTypeRefResolver struct {
	overrides map[string]JsonSchema
	depth int
}

func (r *fromTypeRefResolver) fromTypeRef(operation, definition *ast.Document, typeRef int) JsonSchema {
	r.depth++
	defer func() {
		r.depth--
	}()
	t := operation.Types[typeRef]
	switch t.TypeKind {
	case ast.TypeKindList:
		itemSchema := r.fromTypeRef(operation, definition, t.OfType)
		if operation.TypeIsNonNull(typeRef) {
			min := 1
			return NewArray(itemSchema, &min)
		}
		return NewArray(itemSchema, nil)
	case ast.TypeKindNonNull:
		out := r.fromTypeRef(operation, definition, t.OfType)
		return out
	case ast.TypeKindNamed:
		name := operation.Input.ByteSliceString(t.Name)
		if schema, ok := r.overrides[name]; ok {
			return schema
		}
		typeDefinitionNode, ok := definition.Index.FirstNodeByNameStr(name)
		if !ok {
			return nil
		}
		if typeDefinitionNode.Kind == ast.NodeKindEnumTypeDefinition {
			return NewString()
		}
		if typeDefinitionNode.Kind == ast.NodeKindScalarTypeDefinition {
			switch name {
			case "Boolean":
				return NewBoolean()
			case "String":
				return NewString()
			case "ID":
				return NewID()
			case "Int":
				return NewInteger()
			case "Float":
				return NewNumber()
			case "_Any":
				return NewObjectAny()
			default:
				return NewAny()
			}
		}
		if r.depth > 5 {
			return NewObject()
		}
		object := NewObject()
		if node, ok := definition.Index.FirstNodeByNameStr(name); ok {
			switch node.Kind {
			case ast.NodeKindInputObjectTypeDefinition:
				for _, ref := range definition.InputObjectTypeDefinitions[node.Ref].InputFieldsDefinition.Refs {
					fieldName := definition.Input.ByteSliceString(definition.InputValueDefinitions[ref].Name)
					fieldType := definition.InputValueDefinitions[ref].Type
					fieldSchema := r.fromTypeRef(definition, definition, fieldType)
					object.Properties[fieldName] = fieldSchema
					if definition.TypeIsNonNull(fieldType) {
						object.Required = append(object.Required, fieldName)
					}
				}
			case ast.NodeKindObjectTypeDefinition:
				for _, ref := range definition.ObjectTypeDefinitions[node.Ref].FieldsDefinition.Refs {
					fieldName := definition.Input.ByteSliceString(definition.FieldDefinitions[ref].Name)
					fieldType := definition.FieldDefinitions[ref].Type
					fieldSchema := r.fromTypeRef(definition, definition, fieldType)
					object.Properties[fieldName] = fieldSchema
					if definition.TypeIsNonNull(fieldType) {
						object.Required = append(object.Required, fieldName)
					}
				}
			}
		}
		return object
	}
	return NewObject()
}

type Validator struct {
	schema jsonschema.Schema
}

func NewValidatorFromSchema(schema JsonSchema) (*Validator, error) {
	s, err := json.Marshal(schema)
	if err != nil {
		return nil, err
	}
	return NewValidatorFromString(string(s))
}

func MustNewValidatorFromSchema(schema JsonSchema) *Validator {
	s, err := json.Marshal(schema)
	if err != nil {
		panic(err)
	}
	return MustNewValidatorFromString(string(s))
}

func NewValidatorFromString(schema string) (*Validator, error) {
	var validator Validator
	err := json.Unmarshal([]byte(schema), &validator.schema)
	if err != nil {
		return nil, err
	}
	return &validator, nil
}

func MustNewValidatorFromString(schema string) *Validator {
	var validator Validator
	err := json.Unmarshal([]byte(schema), &validator.schema)
	if err != nil {
		panic(err)
	}
	return &validator
}

func TopLevelType(schema string) (jsonparser.ValueType, error) {
	var jsonSchema jsonschema.Schema
	err := json.Unmarshal([]byte(schema), &jsonSchema)
	if err != nil {
		return jsonparser.Unknown, err
	}
	switch jsonSchema.TopLevelType() {
	case "boolean":
		return jsonparser.Boolean, nil
	case "string":
		return jsonparser.String, nil
	case "object":
		return jsonparser.Object, nil
	case "number":
		return jsonparser.Number, nil
	case "integer":
		return jsonparser.Number, nil
	case "null":
		return jsonparser.Null, nil
	case "array":
		return jsonparser.Array, nil
	default:
		return jsonparser.NotExist, nil
	}
}

func (v *Validator) Validate(ctx context.Context, inputJSON []byte) bool {
	errs, err := v.schema.ValidateBytes(ctx, inputJSON)
	return err == nil && len(errs) == 0
}

type Kind int

const (
	StringKind Kind = iota + 1
	NumberKind
	BooleanKind
	IntegerKind
	ObjectKind
	ArrayKind
	AnyKind
	IDKind
)

type JsonSchema interface {
	Kind() Kind
}

type Any struct{}

func NewAny() Any {
	return Any{}
}

func (a Any) Kind() Kind {
	return AnyKind
}

type String struct {
	Type string `json:"type"`
}

func (_ String) Kind() Kind {
	return StringKind
}

func NewString() String {
	return String{
		Type: "string",
	}
}

type ID struct {
	Type []string `json:"type"`
}

func (_ ID) Kind() Kind {
	return IDKind
}

func NewID() ID {
	return ID{
		Type: []string{"string", "integer"},
	}
}

type Boolean struct {
	Type string `json:"type"`
}

func (_ Boolean) Kind() Kind {
	return BooleanKind
}

func NewBoolean() Boolean {
	return Boolean{
		Type: "boolean",
	}
}

type Number struct {
	Type string `json:"type"`
}

func NewNumber() Number {
	return Number{
		Type: "number",
	}
}

func (_ Number) Kind() Kind {
	return NumberKind
}

type Integer struct {
	Type string `json:"type"`
}

func (_ Integer) Kind() Kind {
	return IntegerKind
}

func NewInteger() Integer {
	return Integer{
		Type: "integer",
	}
}

type Object struct {
	Type                 string                `json:"type"`
	Properties           map[string]JsonSchema `json:"properties,omitempty"`
	Required             []string              `json:"required,omitempty"`
	AdditionalProperties bool                  `json:"additionalProperties"`
}

func (_ Object) Kind() Kind {
	return ObjectKind
}

func NewObject() Object {
	return Object{
		Type:                 "object",
		Properties:           map[string]JsonSchema{},
		AdditionalProperties: false,
	}
}

func NewObjectAny() Object {
	return Object{
		Type:                 "object",
		Properties:           map[string]JsonSchema{},
		AdditionalProperties: true,
	}
}

type Array struct {
	Type     string     `json:"type"`
	Items    JsonSchema `json:"item"`
	MinItems *int       `json:"minItems,omitempty"`
}

func (_ Array) Kind() Kind {
	return ArrayKind
}

func NewArray(itemSchema JsonSchema, minItems *int) Array {
	return Array{
		Type:     "array",
		Items:    itemSchema,
		MinItems: minItems,
	}
}
