package ast

import (
	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

type InterfaceTypeExtension struct {
	ExtendLiteral position.Position
	InterfaceTypeDefinition
}

func (d *Document) InterfaceTypeExtensionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.InterfaceTypeExtensions[ref].Name)
}

func (d *Document) InterfaceTypeExtensionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.InterfaceTypeExtensions[ref].Name))
}

func (d *Document) InterfaceTypeExtensionDescriptionBytes(ref int) ByteSlice {
	if !d.InterfaceTypeExtensions[ref].Description.IsDefined {
		return nil
	}
	return d.Input.ByteSlice(d.InterfaceTypeExtensions[ref].Description.Content)
}

func (d *Document) InterfaceTypeExtensionDescriptionString(ref int) string {
	return unsafebytes.BytesToString(d.InterfaceTypeExtensionDescriptionBytes(ref))
}

func (d *Document) InterfaceTypeExtensionHasFieldDefinitions(ref int) bool {
	return d.InterfaceTypeExtensions[ref].HasFieldDefinitions
}

func (d *Document) InterfaceTypeExtensionHasDirectives(ref int) bool {
	return d.InterfaceTypeExtensions[ref].HasDirectives
}

func (d *Document) ExtendInterfaceTypeDefinitionByInterfaceTypeExtension(interfaceTypeDefinitionRef, interfaceTypeExtensionRef int) {
	if d.InterfaceTypeExtensionHasFieldDefinitions(interfaceTypeExtensionRef) {
		d.InterfaceTypeDefinitions[interfaceTypeDefinitionRef].FieldsDefinition.Refs = append(d.InterfaceTypeDefinitions[interfaceTypeDefinitionRef].FieldsDefinition.Refs, d.InterfaceTypeExtensions[interfaceTypeExtensionRef].FieldsDefinition.Refs...)
		d.InterfaceTypeDefinitions[interfaceTypeDefinitionRef].HasFieldDefinitions = true
	}

	if d.InterfaceTypeExtensionHasDirectives(interfaceTypeExtensionRef) {
		d.InterfaceTypeDefinitions[interfaceTypeDefinitionRef].Directives.Refs = append(d.InterfaceTypeDefinitions[interfaceTypeDefinitionRef].Directives.Refs, d.InterfaceTypeExtensions[interfaceTypeExtensionRef].Directives.Refs...)
		d.InterfaceTypeDefinitions[interfaceTypeDefinitionRef].HasDirectives = true
	}

	d.Index.MergedTypeExtensions = append(d.Index.MergedTypeExtensions, Node{Ref: interfaceTypeExtensionRef, Kind: NodeKindInterfaceTypeExtension})
}

func (d *Document) ImportAndExtendInterfaceTypeDefinitionByInterfaceTypeExtension(interfaceTypeExtensionRef int) {
	d.ImportInterfaceTypeDefinitionWithDirectives(
		d.InterfaceTypeExtensionNameString(interfaceTypeExtensionRef),
		d.InterfaceTypeExtensionDescriptionString(interfaceTypeExtensionRef),
		d.InterfaceTypeExtensions[interfaceTypeExtensionRef].FieldsDefinition.Refs,
		d.InterfaceTypeExtensions[interfaceTypeExtensionRef].Directives.Refs,
	)
	d.Index.MergedTypeExtensions = append(d.Index.MergedTypeExtensions, Node{Ref: interfaceTypeExtensionRef, Kind: NodeKindInterfaceTypeExtension})
}
