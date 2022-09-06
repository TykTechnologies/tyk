package ast

import (
	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

type InputObjectTypeExtension struct {
	ExtendLiteral position.Position
	InputObjectTypeDefinition
}

func (d *Document) InputObjectTypeExtensionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.InputObjectTypeExtensions[ref].Name)
}

func (d *Document) InputObjectTypeExtensionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.InputObjectTypeExtensions[ref].Name))
}

func (d *Document) InputObjectTypeExtensionDescriptionBytes(ref int) ByteSlice {
	if !d.InputObjectTypeExtensions[ref].Description.IsDefined {
		return nil
	}
	return d.Input.ByteSlice(d.InputObjectTypeExtensions[ref].Description.Content)
}

func (d *Document) InputObjectTypeExtensionDescriptionString(ref int) string {
	return unsafebytes.BytesToString(d.InputObjectTypeExtensionDescriptionBytes(ref))
}

func (d *Document) InputObjectTypeExtensionHasInputFieldsDefinition(ref int) bool {
	return d.InputObjectTypeExtensions[ref].HasInputFieldsDefinition
}

func (d *Document) InputObjectTypeExtensionHasDirectives(ref int) bool {
	return d.InputObjectTypeExtensions[ref].HasDirectives
}

func (d *Document) ExtendInputObjectTypeDefinitionByInputObjectTypeExtension(inputObjectTypeDefinitionRef, inputObjectTypeExtensionRef int) {
	if d.InputObjectTypeExtensionHasDirectives(inputObjectTypeExtensionRef) {
		d.InputObjectTypeDefinitions[inputObjectTypeDefinitionRef].Directives.Refs = append(d.InputObjectTypeDefinitions[inputObjectTypeDefinitionRef].Directives.Refs, d.InputObjectTypeExtensions[inputObjectTypeExtensionRef].Directives.Refs...)
		d.InputObjectTypeDefinitions[inputObjectTypeDefinitionRef].HasDirectives = true
	}

	if d.InputObjectTypeExtensionHasInputFieldsDefinition(inputObjectTypeExtensionRef) {
		d.InputObjectTypeDefinitions[inputObjectTypeDefinitionRef].InputFieldsDefinition.Refs = append(d.InputObjectTypeDefinitions[inputObjectTypeDefinitionRef].InputFieldsDefinition.Refs, d.InputObjectTypeExtensions[inputObjectTypeExtensionRef].InputFieldsDefinition.Refs...)
		d.InputObjectTypeDefinitions[inputObjectTypeDefinitionRef].HasInputFieldsDefinition = true
	}

	d.Index.MergedTypeExtensions = append(d.Index.MergedTypeExtensions, Node{Ref: inputObjectTypeExtensionRef, Kind: NodeKindInputObjectTypeExtension})
}

func (d *Document) ImportAndExtendInputObjectTypeDefinitionByInputObjectTypeExtension(inputObjectTypeExtensionRef int) {
	d.ImportInputObjectTypeDefinitionWithDirectives(
		d.InputObjectTypeExtensionNameString(inputObjectTypeExtensionRef),
		d.InputObjectTypeExtensionDescriptionString(inputObjectTypeExtensionRef),
		d.InputObjectTypeExtensions[inputObjectTypeExtensionRef].InputFieldsDefinition.Refs,
		d.InputObjectTypeExtensions[inputObjectTypeExtensionRef].Directives.Refs,
	)
	d.Index.MergedTypeExtensions = append(d.Index.MergedTypeExtensions, Node{Ref: inputObjectTypeExtensionRef, Kind: NodeKindInputObjectTypeExtension})
}
