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

func (d *Document) EnumTypeExtensionDescriptionBytes(ref int) ByteSlice {
	if !d.EnumTypeExtensions[ref].Description.IsDefined {
		return nil
	}
	return d.Input.ByteSlice(d.EnumTypeExtensions[ref].Description.Content)
}

func (d *Document) EnumTypeExtensionDescriptionString(ref int) string {
	return unsafebytes.BytesToString(d.EnumTypeExtensionDescriptionBytes(ref))
}

func (d *Document) EnumTypeExtensionHasEnumValueDefinition(ref int) bool {
	return d.EnumTypeExtensions[ref].HasEnumValuesDefinition
}

func (d *Document) EnumTypeExtensionHasDirectives(ref int) bool {
	return d.EnumTypeExtensions[ref].HasDirectives
}

func (d *Document) ExtendEnumTypeDefinitionByEnumTypeExtension(enumTypeDefinitionRef, enumTypeExtensionRef int) {
	if d.EnumTypeExtensionHasDirectives(enumTypeExtensionRef) {
		d.EnumTypeDefinitions[enumTypeDefinitionRef].Directives.Refs = append(d.EnumTypeDefinitions[enumTypeDefinitionRef].Directives.Refs, d.EnumTypeExtensions[enumTypeExtensionRef].Directives.Refs...)
		d.EnumTypeDefinitions[enumTypeDefinitionRef].HasDirectives = true
	}

	if d.EnumTypeExtensionHasEnumValueDefinition(enumTypeExtensionRef) {
		d.EnumTypeDefinitions[enumTypeDefinitionRef].EnumValuesDefinition.Refs = append(d.EnumTypeDefinitions[enumTypeDefinitionRef].EnumValuesDefinition.Refs, d.EnumTypeExtensions[enumTypeExtensionRef].EnumValuesDefinition.Refs...)
		d.EnumTypeDefinitions[enumTypeDefinitionRef].HasEnumValuesDefinition = true
	}

	d.Index.MergedTypeExtensions = append(d.Index.MergedTypeExtensions, Node{Ref: enumTypeExtensionRef, Kind: NodeKindEnumTypeExtension})
}

func (d *Document) ImportAndExtendEnumTypeDefinitionByEnumTypeExtension(enumTypeExtensionRef int) {
	d.ImportEnumTypeDefinitionWithDirectives(
		d.EnumTypeExtensionNameString(enumTypeExtensionRef),
		d.EnumTypeExtensionDescriptionString(enumTypeExtensionRef),
		d.EnumTypeExtensions[enumTypeExtensionRef].EnumValuesDefinition.Refs,
		d.EnumTypeExtensions[enumTypeExtensionRef].Directives.Refs,
	)
	d.Index.MergedTypeExtensions = append(d.Index.MergedTypeExtensions, Node{Ref: enumTypeExtensionRef, Kind: NodeKindEnumTypeExtension})
}
