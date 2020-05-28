package ast

import (
	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

// ScalarTypeDefinition
// example:
// scalar JSON
type ScalarTypeDefinition struct {
	Description   Description        // optional, describes the scalar
	ScalarLiteral position.Position  // scalar
	Name          ByteSliceReference // e.g. JSON
	HasDirectives bool
	Directives    DirectiveList // optional, e.g. @foo
}

func (d *Document) ScalarTypeDefinitionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.ScalarTypeDefinitions[ref].Name)
}

func (d *Document) ScalarTypeDefinitionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.ScalarTypeDefinitions[ref].Name))
}

func (d *Document) ScalarTypeDefinitionDescriptionBytes(ref int) ByteSlice {
	if !d.ScalarTypeDefinitions[ref].Description.IsDefined {
		return nil
	}
	return d.Input.ByteSlice(d.ScalarTypeDefinitions[ref].Description.Content)
}

func (d *Document) ScalarTypeDefinitionDescriptionString(ref int) string {
	return unsafebytes.BytesToString(d.ScalarTypeDefinitionDescriptionBytes(ref))
}

func (d *Document) ScalarTypeDefinitionHasDirectives(ref int) bool {
	return d.ScalarTypeDefinitions[ref].HasDirectives
}

func (d *Document) AddScalarTypeDefinition(definition ScalarTypeDefinition) (ref int) {
	d.ScalarTypeDefinitions = append(d.ScalarTypeDefinitions, definition)
	return len(d.ScalarTypeDefinitions) - 1
}

func (d *Document) ImportScalarTypeDefinition(name, description string) (ref int) {
	definition := ScalarTypeDefinition{
		Description: d.ImportDescription(description),
		Name:        d.Input.AppendInputString(name),
	}

	ref = d.AddScalarTypeDefinition(definition)
	d.ImportRootNode(ref, NodeKindScalarTypeDefinition)

	return
}
