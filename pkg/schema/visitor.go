package schema

import (
	"errors"
	"regexp"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

var (
	unicodeRegex = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	re2Regex     = regexp.MustCompile(`\\x\{([0-9a-fA-F]{4})}`)
)

func NewVisitor() *Visitor {
	return &Visitor{
		manipulations: make(Manipulations, 0),
		visited:       make(map[*openapi3.Schema]bool),
	}
}

type Manipulation func(schema *openapi3.Schema)
type Manipulations []Manipulation

type Visitor struct {
	manipulations Manipulations

	visited map[*openapi3.Schema]bool
}

func (v *Visitor) AddSchemaManipulation(manipulation Manipulation) {
	v.manipulations = append(v.manipulations, manipulation)
}

func (v *Visitor) ProcessOAS(doc *oas.OAS) {
	if doc.Components != nil && doc.Components.Schemas != nil {
		for _, schemaRef := range doc.Components.Schemas {
			v.ProcessSchema(schemaRef)
		}
	}

	if doc.Paths != nil {
		v.processOASPaths(doc.Paths.Map())
	}
}

func (v *Visitor) ProcessSchema(schemaRef *openapi3.SchemaRef) {
	if schemaRef == nil || schemaRef.Value == nil {
		return
	}

	if v.isVisited(schemaRef.Value) {
		return
	}

	v.applyManipulations(schemaRef.Value)

	for _, propSchemaRef := range schemaRef.Value.Properties {
		v.ProcessSchema(propSchemaRef)
	}
	if schemaRef.Value.Items != nil {
		v.ProcessSchema(schemaRef.Value.Items)
	}
	if schemaRef.Value.AdditionalProperties.Schema != nil {
		v.ProcessSchema(schemaRef.Value.AdditionalProperties.Schema)
	}
	if schemaRef.Value.Not != nil {
		v.ProcessSchema(schemaRef.Value.Not)
	}
	for _, subSchemaRef := range schemaRef.Value.AllOf {
		v.ProcessSchema(subSchemaRef)
	}
	for _, subSchemaRef := range schemaRef.Value.AnyOf {
		v.ProcessSchema(subSchemaRef)
	}
	for _, subSchemaRef := range schemaRef.Value.OneOf {
		v.ProcessSchema(subSchemaRef)
	}
}

func (v *Visitor) processOASPaths(paths map[string]*openapi3.PathItem) {
	for _, pathItem := range paths {
		if pathItem == nil {
			continue
		}
		for _, op := range pathItem.Operations() {
			v.processOperationParameters(op)
			v.processOperationContent(op)
			v.processOperationResponses(op)
			v.processOperationCallbacks(op)
		}
	}
}

func (v *Visitor) processOperationCallbacks(op *openapi3.Operation) {
	for _, callbackRef := range op.Callbacks {
		if callbackRef.Value != nil {
			v.processOASPaths(callbackRef.Value.Map())
		}
	}
}

func (v *Visitor) processOperationResponses(op *openapi3.Operation) {
	for _, respRef := range op.Responses.Map() {
		if respRef.Value != nil {
			for _, mediaType := range respRef.Value.Content {
				v.ProcessSchema(mediaType.Schema)
			}
			for _, header := range respRef.Value.Headers {
				if header.Value != nil {
					v.ProcessSchema(header.Value.Schema)
				}
			}
		}
	}
}

func (v *Visitor) processOperationContent(op *openapi3.Operation) {
	if op.RequestBody != nil && op.RequestBody.Value != nil {
		for _, mediaType := range op.RequestBody.Value.Content {
			v.ProcessSchema(mediaType.Schema)
		}
	}
}

func (v *Visitor) processOperationParameters(op *openapi3.Operation) {
	for _, paramRef := range op.Parameters {
		if paramRef.Value != nil && paramRef.Value.Schema != nil {
			v.ProcessSchema(paramRef.Value.Schema)
		}
	}
}

func (v *Visitor) applyManipulations(schema *openapi3.Schema) {
	for _, operation := range v.manipulations {
		operation(schema)
	}
}

func (v *Visitor) isVisited(schema *openapi3.Schema) bool {
	if _, ok := v.visited[schema]; ok {
		return true
	}

	v.visited[schema] = true
	return false
}

func (v *Visitor) resetVisited() {
	v.visited = make(map[*openapi3.Schema]bool)
}

func TransformUnicodeEscapesToRE2Manipulation(schema *openapi3.Schema) {
	if schema == nil || schema.Pattern == "" {
		return
	}

	schema.Pattern = unicodeRegex.ReplaceAllStringFunc(schema.Pattern, func(match string) string {
		var sb strings.Builder
		sb.WriteString(`\x{`)
		sb.WriteString(match[2:])
		sb.WriteString(`}`)

		return sb.String()
	})
}

func RestoreUnicodeEscapesFromRE2Manipulation(schema *openapi3.Schema) {
	if schema == nil || schema.Pattern == "" {
		return
	}

	schema.Pattern = RestoreUnicodeEscapesFromRE2(schema.Pattern)
}

func RestoreUnicodeEscapesFromRE2(str string) string {
	return re2Regex.ReplaceAllStringFunc(str, func(match string) string {
		var sb strings.Builder
		sb.WriteString(`\u`)
		sb.WriteString(match[3:7])

		return sb.String()
	})
}

func RestoreUnicodeEscapesInError(err error) error {
	if err == nil {
		return nil
	}

	return errors.New(RestoreUnicodeEscapesFromRE2(err.Error()))
}
