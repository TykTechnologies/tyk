package ast

import (
	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

type EnumTypeExtension struct {
	ExtendLiteral position.Position
	EnumTypeDefinition
}

func (d *Document) EnumTypeExtensionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.EnumTypeExtensions[ref].Name)
}

func (d *Document) EnumTypeExtensionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.EnumTypeExtensions[ref].Name))
}

func (d *Document) EnumTypeExtensionHasDirectives(ref int) bool {
	return d.EnumTypeExtensions[ref].HasDirectives
}

func (d *Document) ExtendEnumTypeDefinitionByEnumTypeExtension(enumTypeDefinitionRef, enumTypeExtensionRef int) {
	if d.EnumTypeExtensionHasDirectives(enumTypeExtensionRef) {
		d.EnumTypeDefinitions[enumTypeDefinitionRef].Directives.Refs = append(d.EnumTypeDefinitions[enumTypeDefinitionRef].Directives.Refs, d.EnumTypeExtensions[enumTypeExtensionRef].Directives.Refs...)
		d.EnumTypeDefinitions[enumTypeDefinitionRef].HasDirectives = true
	}

	if d.EnumTypeDefinitionHasEnumValueDefinition(enumTypeExtensionRef) {
		d.EnumTypeDefinitions[enumTypeDefinitionRef].EnumValuesDefinition.Refs = append(d.EnumTypeDefinitions[enumTypeDefinitionRef].EnumValuesDefinition.Refs, d.EnumTypeExtensions[enumTypeExtensionRef].EnumValuesDefinition.Refs...)
		d.EnumTypeDefinitions[enumTypeDefinitionRef].HasEnumValuesDefinition = true
	}

	d.Index.MergedTypeExtensions = append(d.Index.MergedTypeExtensions, Node{Ref: enumTypeExtensionRef, Kind: NodeKindEnumTypeExtension})
}
