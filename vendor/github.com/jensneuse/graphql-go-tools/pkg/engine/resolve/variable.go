package resolve

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"

	"github.com/buger/jsonparser"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/graphqljsonschema"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
)

var (
	ErrInvalidJsonSchema = errors.New("json schema validation failed on Variable Renderer")
)

type VariableKind int

const (
	ContextVariableKind VariableKind = iota + 1
	ObjectVariableKind
	HeaderVariableKind
)

// VariableRenderer is the interface to allow custom implementations of rendering Variables
// Depending on where a Variable is being used, a different method for rendering is required
// E.g. a Variable needs to be rendered conforming to the GraphQL specification, when used within a GraphQL Query
// If a Variable is used within a JSON Object, the contents need to be rendered as a JSON Object
type VariableRenderer interface {
	RenderVariable(ctx context.Context, data []byte, out io.Writer) error
}

// JSONVariableRenderer is an implementation of VariableRenderer
// It renders the provided data as JSON
// If configured, it also does a JSON Validation Check before rendering
type JSONVariableRenderer struct {
	JSONSchema    string
	Kind          string
	validator     *graphqljsonschema.Validator
	rootValueType JsonRootType
}

func (r *JSONVariableRenderer) RenderVariable(ctx context.Context, data []byte, out io.Writer) error {
	if r.validator != nil {
		valid := r.validator.Validate(ctx, data)
		if !valid {
			return ErrInvalidJsonSchema
		}
	}
	_, err := out.Write(data)
	return err
}

func NewJSONVariableRenderer() *JSONVariableRenderer {
	return &JSONVariableRenderer{
		Kind: "json",
	}
}

func NewJSONVariableRendererWithValidation(jsonSchema string) *JSONVariableRenderer {
	validator := graphqljsonschema.MustNewValidatorFromString(jsonSchema)
	return &JSONVariableRenderer{
		Kind:       "jsonWithValidation",
		JSONSchema: jsonSchema,
		validator:  validator,
	}
}

// NewJSONVariableRendererWithValidationFromTypeRef creates a new JSONVariableRenderer
// The argument typeRef must exist on the operation ast.Document, otherwise it will panic!
func NewJSONVariableRendererWithValidationFromTypeRef(operation, definition *ast.Document, variableTypeRef int) (*JSONVariableRenderer, error) {
	jsonSchema := graphqljsonschema.FromTypeRef(operation, definition, variableTypeRef)
	validator, err := graphqljsonschema.NewValidatorFromSchema(jsonSchema)
	if err != nil {
		return nil, err
	}
	schemaBytes, err := json.Marshal(jsonSchema)
	if err != nil {
		return nil, err
	}
	return &JSONVariableRenderer{
		Kind:          "jsonWithValidation",
		JSONSchema:    string(schemaBytes),
		validator:     validator,
		rootValueType: getJSONRootType(operation, definition, variableTypeRef),
	}, nil
}

func NewPlainVariableRenderer() *PlainVariableRenderer {
	return &PlainVariableRenderer{
		Kind: "plain",
	}
}

func NewPlainVariableRendererWithValidation(jsonSchema string) *PlainVariableRenderer {
	validator := graphqljsonschema.MustNewValidatorFromString(jsonSchema)
	return &PlainVariableRenderer{
		Kind:       "plainWithValidation",
		JSONSchema: jsonSchema,
		validator:  validator,
	}
}

// NewPlainVariableRendererWithValidationFromTypeRef creates a new PlainVariableRenderer
// The argument typeRef must exist on the operation ast.Document, otherwise it will panic!
func NewPlainVariableRendererWithValidationFromTypeRef(operation, definition *ast.Document, variableTypeRef int) (*PlainVariableRenderer, error) {
	jsonSchema := graphqljsonschema.FromTypeRef(operation, definition, variableTypeRef)
	validator, err := graphqljsonschema.NewValidatorFromSchema(jsonSchema)
	if err != nil {
		return nil, err
	}
	schemaBytes, err := json.Marshal(jsonSchema)
	if err != nil {
		return nil, err
	}
	rootValueType := getJSONRootType(operation, definition, variableTypeRef)
	return &PlainVariableRenderer{
		Kind:          "plainWithValidation",
		JSONSchema:    string(schemaBytes),
		validator:     validator,
		rootValueType: rootValueType,
	}, nil
}

// PlainVariableRenderer is an implementation of VariableRenderer
// It renders the provided data as plain text
// E.g. a provided JSON string of "foo" will be rendered as foo, without quotes.
// If a nested JSON Object is provided, it will be rendered as is.
// This renderer can be used e.g. to render the provided scalar into a URL.
type PlainVariableRenderer struct {
	JSONSchema    string
	Kind          string
	validator     *graphqljsonschema.Validator
	rootValueType JsonRootType
}

func (p *PlainVariableRenderer) RenderVariable(ctx context.Context, data []byte, out io.Writer) error {
	if p.validator != nil {
		valid := p.validator.Validate(ctx, data)
		if !valid {
			return ErrInvalidJsonSchema
		}
	}

	data, _ = extractStringWithQuotes(p.rootValueType, data)

	_, err := out.Write(data)
	return err
}

// NewGraphQLVariableRendererFromTypeRef creates a new GraphQLVariableRenderer
// The argument typeRef must exist on the operation ast.Document, otherwise it will panic!
func NewGraphQLVariableRendererFromTypeRef(operation, definition *ast.Document, variableTypeRef int) (*GraphQLVariableRenderer, error) {
	jsonSchema := graphqljsonschema.FromTypeRef(operation, definition, variableTypeRef)
	validator, err := graphqljsonschema.NewValidatorFromSchema(jsonSchema)
	if err != nil {
		return nil, err
	}
	schemaBytes, err := json.Marshal(jsonSchema)
	if err != nil {
		return nil, err
	}
	return &GraphQLVariableRenderer{
		Kind:          "graphqlWithValidation",
		JSONSchema:    string(schemaBytes),
		validator:     validator,
		rootValueType: getJSONRootType(operation, definition, variableTypeRef),
	}, nil
}

func NewGraphQLVariableRendererFromTypeRefWithOverrides(operation, definition *ast.Document, variableTypeRef int, overrides map[string]graphqljsonschema.JsonSchema) (*GraphQLVariableRenderer, error) {
	jsonSchema := graphqljsonschema.FromTypeRefWithOverrides(operation, definition, variableTypeRef,overrides)
	validator, err := graphqljsonschema.NewValidatorFromSchema(jsonSchema)
	if err != nil {
		return nil, err
	}
	schemaBytes, err := json.Marshal(jsonSchema)
	if err != nil {
		return nil, err
	}
	return &GraphQLVariableRenderer{
		Kind:          "graphqlWithValidation",
		JSONSchema:    string(schemaBytes),
		validator:     validator,
		rootValueType: getJSONRootType(operation, definition, variableTypeRef),
	}, nil
}

func NewGraphQLVariableRendererFromTypeRefWithoutValidation(operation, definition *ast.Document, variableTypeRef int) (*GraphQLVariableRenderer, error) {
	return &GraphQLVariableRenderer{
		Kind:          "graphqlWithValidation",
		rootValueType: getJSONRootType(operation, definition, variableTypeRef),
	}, nil
}

// NewGraphQLVariableRenderer - to be used in tests only
func NewGraphQLVariableRenderer(jsonSchema string) *GraphQLVariableRenderer {
	validator := graphqljsonschema.MustNewValidatorFromString(jsonSchema)
	rootValueType, err := graphqljsonschema.TopLevelType(jsonSchema)
	if err != nil {
		panic(err)
	}
	return &GraphQLVariableRenderer{
		Kind:       "graphqlWithValidation",
		JSONSchema: jsonSchema,
		validator:  validator,
		rootValueType: JsonRootType{
			Value: rootValueType,
			Kind:  JsonRootTypeKindSingle,
		},
	}
}

type JsonRootTypeKind int

const (
	JsonRootTypeKindSingle JsonRootTypeKind = iota
	JsonRootTypeKindMultiple
)

type JsonRootType struct {
	Value  jsonparser.ValueType
	Values []jsonparser.ValueType
	Kind   JsonRootTypeKind
}

func (t JsonRootType) Satisfies(dataType jsonparser.ValueType) bool {
	switch t.Kind {
	case JsonRootTypeKindSingle:
		return dataType == t.Value
	case JsonRootTypeKindMultiple:
		for _, valueType := range t.Values {
			if dataType == valueType {
				return true
			}
		}
	}

	return false
}

func getJSONRootType(operation, definition *ast.Document, variableTypeRef int) JsonRootType {
	variableTypeRef = operation.ResolveListOrNameType(variableTypeRef)
	if operation.TypeIsList(variableTypeRef) {
		return JsonRootType{
			Value: jsonparser.Array,
			Kind:  JsonRootTypeKindSingle,
		}
	}

	name := operation.TypeNameString(variableTypeRef)
	node, exists := definition.Index.FirstNodeByNameStr(name)
	if !exists {
		return JsonRootType{
			Value: jsonparser.Unknown,
			Kind:  JsonRootTypeKindSingle,
		}
	}

	defTypeRef := node.Ref

	if node.Kind == ast.NodeKindEnumTypeDefinition {
		return JsonRootType{
			Value: jsonparser.String,
			Kind:  JsonRootTypeKindSingle,
		}
	}
	if node.Kind == ast.NodeKindScalarTypeDefinition {
		typeName := definition.ScalarTypeDefinitionNameString(defTypeRef)
		switch typeName {
		case "Boolean":
			return JsonRootType{
				Value: jsonparser.Boolean,
				Kind:  JsonRootTypeKindSingle,
			}
		case "Int", "Float":
			return JsonRootType{
				Value: jsonparser.Number,
				Kind:  JsonRootTypeKindSingle,
			}
		case "ID":
			return JsonRootType{
				Values: []jsonparser.ValueType{jsonparser.String, jsonparser.Number},
				Kind:   JsonRootTypeKindMultiple,
			}
		case "String", "Date":
			return JsonRootType{
				Value: jsonparser.String,
				Kind:  JsonRootTypeKindSingle,
			}
		case "_Any":
			return JsonRootType{
				Value: jsonparser.Object,
				Kind:  JsonRootTypeKindSingle,
			}
		default:
			return JsonRootType{
				Value: jsonparser.String,
				Kind:  JsonRootTypeKindSingle,
			}
		}
	}

	return JsonRootType{
		Value: jsonparser.Object,
		Kind:  JsonRootTypeKindSingle,
	}
}

// GraphQLVariableRenderer is an implementation of VariableRenderer
// It renders variables according to the GraphQL Specification
type GraphQLVariableRenderer struct {
	JSONSchema    string
	Kind          string
	validator     *graphqljsonschema.Validator
	rootValueType JsonRootType
}

// add renderer that renders both variable name and variable value
// before rendering, evaluate if the value contains null values
// if an object contains only null values, set the object to null
// do this recursively until reaching the root of the object


func (g *GraphQLVariableRenderer) RenderVariable(ctx context.Context, data []byte, out io.Writer) error {
	if g.validator != nil {
		valid := g.validator.Validate(ctx, data)
		if !valid {
			return ErrInvalidJsonSchema
		}
	}

	var desiredType jsonparser.ValueType
	data, desiredType = extractStringWithQuotes(g.rootValueType, data)

	return g.renderGraphQLValue(data, desiredType, out)
}

func (g *GraphQLVariableRenderer) renderGraphQLValue(data []byte, valueType jsonparser.ValueType, out io.Writer) (err error) {
	switch valueType {
	case jsonparser.String:
		_, _ = out.Write(literal.BACKSLASH)
		_, _ = out.Write(literal.QUOTE)
		for i := range data {
			switch data[i] {
			case '"':
				_, _ = out.Write(literal.BACKSLASH)
				_, _ = out.Write(literal.BACKSLASH)
				_, _ = out.Write(literal.QUOTE)
			default:
				_, _ = out.Write(data[i : i+1])
			}
		}
		_, _ = out.Write(literal.BACKSLASH)
		_, _ = out.Write(literal.QUOTE)
	case jsonparser.Object:
		_, _ = out.Write(literal.LBRACE)
		first := true
		err = jsonparser.ObjectEach(data, func(key []byte, value []byte, objectFieldValueType jsonparser.ValueType, offset int) error {
			if !first {
				_, _ = out.Write(literal.COMMA)
			} else {
				first = false
			}
			_, _ = out.Write(key)
			_, _ = out.Write(literal.COLON)
			return g.renderGraphQLValue(value, objectFieldValueType, out)
		})
		if err != nil {
			return err
		}
		_, _ = out.Write(literal.RBRACE)
	case jsonparser.Null:
		_, _ = out.Write(literal.NULL)
	case jsonparser.Boolean:
		_, _ = out.Write(data)
	case jsonparser.Array:
		_, _ = out.Write(literal.LBRACK)
		first := true
		var arrayErr error
		_, err = jsonparser.ArrayEach(data, func(value []byte, arrayItemValueType jsonparser.ValueType, offset int, err error) {
			if !first {
				_, _ = out.Write(literal.COMMA)
			} else {
				first = false
			}
			arrayErr = g.renderGraphQLValue(value, arrayItemValueType, out)
		})
		if arrayErr != nil {
			return arrayErr
		}
		if err != nil {
			return err
		}
		_, _ = out.Write(literal.RBRACK)
	case jsonparser.Number:
		_, _ = out.Write(data)
	}
	return
}

func NewCSVVariableRenderer(arrayValueType JsonRootType) *CSVVariableRenderer {
	return &CSVVariableRenderer{
		Kind:           "csv",
		arrayValueType: arrayValueType,
	}
}

func NewCSVVariableRendererFromTypeRef(operation, definition *ast.Document, variableTypeRef int) *CSVVariableRenderer {
	return &CSVVariableRenderer{
		Kind:           "csv",
		arrayValueType: getJSONRootType(operation, definition, variableTypeRef),
	}
}

// CSVVariableRenderer is an implementation of VariableRenderer
// It renders the provided list of Values as comma separated Values in plaintext (no JSON encoding of Values)
type CSVVariableRenderer struct {
	Kind           string
	arrayValueType JsonRootType
}

func (c *CSVVariableRenderer) RenderVariable(_ context.Context, data []byte, out io.Writer) error {
	isFirst := true
	_, err := jsonparser.ArrayEach(data, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		if !c.arrayValueType.Satisfies(dataType) {
			return
		}

		if isFirst {
			isFirst = false
		} else {
			_, _ = out.Write(literal.COMMA)
		}
		_, _ = out.Write(value)
	})
	return err
}

type ContextVariable struct {
	Path     []string
	Renderer VariableRenderer
}

func (c *ContextVariable) TemplateSegment() TemplateSegment {
	return TemplateSegment{
		SegmentType:        VariableSegmentType,
		VariableKind:       ContextVariableKind,
		VariableSourcePath: c.Path,
		Renderer:           c.Renderer,
	}
}

func (c *ContextVariable) Equals(another Variable) bool {
	if another == nil {
		return false
	}
	if another.GetVariableKind() != c.GetVariableKind() {
		return false
	}
	anotherContextVariable := another.(*ContextVariable)
	if len(c.Path) != len(anotherContextVariable.Path) {
		return false
	}
	for i := range c.Path {
		if c.Path[i] != anotherContextVariable.Path[i] {
			return false
		}
	}
	return true
}

func (_ *ContextVariable) GetVariableKind() VariableKind {
	return ContextVariableKind
}

type ObjectVariable struct {
	Path     []string
	Renderer VariableRenderer
}

func (o *ObjectVariable) TemplateSegment() TemplateSegment {
	return TemplateSegment{
		SegmentType:        VariableSegmentType,
		VariableKind:       ObjectVariableKind,
		VariableSourcePath: o.Path,
		Renderer:           o.Renderer,
	}
}

func (o *ObjectVariable) Equals(another Variable) bool {
	if another == nil {
		return false
	}
	if another.GetVariableKind() != o.GetVariableKind() {
		return false
	}
	anotherObjectVariable := another.(*ObjectVariable)
	if len(o.Path) != len(anotherObjectVariable.Path) {
		return false
	}
	for i := range o.Path {
		if o.Path[i] != anotherObjectVariable.Path[i] {
			return false
		}
	}
	return true
}

func (o *ObjectVariable) GetVariableKind() VariableKind {
	return ObjectVariableKind
}

type HeaderVariable struct {
	Path []string
}

func (h *HeaderVariable) TemplateSegment() TemplateSegment {
	return TemplateSegment{
		SegmentType:        VariableSegmentType,
		VariableKind:       HeaderVariableKind,
		VariableSourcePath: h.Path,
	}
}

func (h *HeaderVariable) GetVariableKind() VariableKind {
	return HeaderVariableKind
}

func (h *HeaderVariable) Equals(another Variable) bool {
	if another == nil {
		return false
	}
	if another.GetVariableKind() != h.GetVariableKind() {
		return false
	}
	anotherHeaderVariable := another.(*HeaderVariable)
	if len(h.Path) != len(anotherHeaderVariable.Path) {
		return false
	}
	for i := range h.Path {
		if h.Path[i] != anotherHeaderVariable.Path[i] {
			return false
		}
	}
	return true
}

type Variable interface {
	GetVariableKind() VariableKind
	Equals(another Variable) bool
	TemplateSegment() TemplateSegment
}

type Variables []Variable

func NewVariables(variables ...Variable) Variables {
	return variables
}

const (
	variablePrefixSuffix = "$$"
)

func (v *Variables) AddVariable(variable Variable) (name string, exists bool) {
	index := -1
	for i := range *v {
		if (*v)[i].Equals(variable) {
			index = i
			exists = true
			break
		}
	}
	if index == -1 {
		*v = append(*v, variable)
		index = len(*v) - 1
	}
	i := strconv.Itoa(index)
	name = variablePrefixSuffix + i + variablePrefixSuffix
	return
}

type VariableSchema struct {
}

func extractStringWithQuotes(rootValueType JsonRootType, data []byte) ([]byte, jsonparser.ValueType) {
	desiredType := jsonparser.Unknown
	switch rootValueType.Kind {
	case JsonRootTypeKindSingle:
		desiredType = rootValueType.Value
	case JsonRootTypeKindMultiple:
		_, tt, _, _ := jsonparser.Get(data)
		if rootValueType.Satisfies(tt) {
			desiredType = tt
		}
	}
	if desiredType == jsonparser.String {
		return data[1 : len(data)-1], desiredType
	}
	return data, desiredType
}
