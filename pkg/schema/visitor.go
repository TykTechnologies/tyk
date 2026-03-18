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

func NewVisitor(doc *oas.OAS) *Visitor {
	return &Visitor{
		doc:           doc,
		manipulations: make(Manipulations, 0),
		visited:       make(map[*openapi3.Schema]bool),
	}
}

type Manipulation func(schema *openapi3.Schema)
type Manipulations []Manipulation

type Visitor struct {
	doc           *oas.OAS
	manipulations Manipulations

	visited map[*openapi3.Schema]bool
}

func (v *Visitor) AddSchemaManipulation(manipulation Manipulation) {
	v.manipulations = append(v.manipulations, manipulation)
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

func (v *Visitor) ProcessOAS() {
	if v.doc.Components != nil && v.doc.Components.Schemas != nil {
		for _, schemaRef := range v.doc.Components.Schemas {
			v.processSchema(schemaRef)
		}
	}

	if v.doc.Paths != nil {
		for _, pathItem := range v.doc.Paths.Map() {
			if pathItem == nil {
				continue
			}
			for _, op := range pathItem.Operations() {
				for _, paramRef := range op.Parameters {
					if paramRef.Value != nil && paramRef.Value.Schema != nil {
						v.processSchema(paramRef.Value.Schema)
					}
				}
				if op.RequestBody != nil && op.RequestBody.Value != nil {
					for _, mediaType := range op.RequestBody.Value.Content {
						v.processSchema(mediaType.Schema)
					}
				}
				for _, respRef := range op.Responses.Map() {
					if respRef.Value != nil {
						for _, mediaType := range respRef.Value.Content {
							v.processSchema(mediaType.Schema)
						}
					}
				}
			}
		}
	}
}

func (v *Visitor) processSchema(schemaRef *openapi3.SchemaRef) {
	if schemaRef == nil || schemaRef.Value == nil {
		return
	}

	if v.isVisited(schemaRef.Value) {
		return
	}

	v.applyManipulations(schemaRef.Value)

	for _, propSchemaRef := range schemaRef.Value.Properties {
		v.processSchema(propSchemaRef)
	}
	if schemaRef.Value.Items != nil {
		v.processSchema(schemaRef.Value.Items)
	}
	if schemaRef.Value.AdditionalProperties.Schema != nil {
		v.processSchema(schemaRef.Value.AdditionalProperties.Schema)
	}
	if schemaRef.Value.Not != nil {
		v.processSchema(schemaRef.Value.Not)
	}
	for _, subSchemaRef := range schemaRef.Value.AllOf {
		v.processSchema(subSchemaRef)
	}
	for _, subSchemaRef := range schemaRef.Value.AnyOf {
		v.processSchema(subSchemaRef)
	}
	for _, subSchemaRef := range schemaRef.Value.OneOf {
		v.processSchema(subSchemaRef)
	}
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
