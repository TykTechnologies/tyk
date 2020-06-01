package ast

import (
	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

type ScalarTypeExtension struct {
	ExtendLiteral position.Position
	ScalarTypeDefinition
}

func (d *Document) ScalarTypeExtensionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.ScalarTypeExtensions[ref].Name)
}

func (d *Document) ScalarTypeExtensionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.ScalarTypeExtensions[ref].Name))
}

func (d *Document) ScalarTypeExtensionHasDirectives(ref int) bool {
	return d.ScalarTypeExtensions[ref].HasDirectives
}

func (d *Document) ExtendScalarTypeDefinitionByScalarTypeExtension(scalarTypeDefinitionRef, scalarTypeExtensionRef int) {
	if d.ScalarTypeExtensionHasDirectives(scalarTypeExtensionRef) {
		d.ScalarTypeDefinitions[scalarTypeDefinitionRef].Directives.Refs = append(d.ScalarTypeDefinitions[scalarTypeDefinitionRef].Directives.Refs, d.ScalarTypeExtensions[scalarTypeExtensionRef].Directives.Refs...)
		d.ScalarTypeDefinitions[scalarTypeDefinitionRef].HasDirectives = true
	}

	d.Index.MergedTypeExtensions = append(d.Index.MergedTypeExtensions, Node{Ref: scalarTypeExtensionRef, Kind: NodeKindScalarTypeExtension})
}
