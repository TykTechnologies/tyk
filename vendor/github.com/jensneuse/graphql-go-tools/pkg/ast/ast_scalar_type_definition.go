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

func (d *Document) ScalarTypeDefinitionHasDirectives(ref int) bool {
	return d.ScalarTypeDefinitions[ref].HasDirectives
}
