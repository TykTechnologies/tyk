package ast

import (
	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

type ObjectTypeExtension struct {
	ExtendLiteral position.Position
	ObjectTypeDefinition
}

func (d *Document) ObjectTypeExtensionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.ObjectTypeExtensions[ref].Name)
}

func (d *Document) ObjectTypeExtensionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.ObjectTypeExtensions[ref].Name))
}

func (d *Document) ObjectTypeExtensionHasFieldDefinitions(ref int) bool {
	return d.ObjectTypeExtensions[ref].HasFieldDefinitions
}

func (d *Document) ObjectTypeExtensionHasDirectives(ref int) bool {
	return d.ObjectTypeExtensions[ref].HasDirectives
}

func (d *Document) ExtendObjectTypeDefinitionByObjectTypeExtension(objectTypeDefinitionRef, objectTypeExtensionRef int) {
	if d.ObjectTypeExtensionHasFieldDefinitions(objectTypeExtensionRef) {
		d.ObjectTypeDefinitions[objectTypeDefinitionRef].FieldsDefinition.Refs = append(d.ObjectTypeDefinitions[objectTypeDefinitionRef].FieldsDefinition.Refs, d.ObjectTypeExtensions[objectTypeExtensionRef].FieldsDefinition.Refs...)
		d.ObjectTypeDefinitions[objectTypeDefinitionRef].HasFieldDefinitions = true
	}

	if d.ObjectTypeExtensionHasDirectives(objectTypeExtensionRef) {
		d.ObjectTypeDefinitions[objectTypeDefinitionRef].Directives.Refs = append(d.ObjectTypeDefinitions[objectTypeDefinitionRef].Directives.Refs, d.ObjectTypeExtensions[objectTypeExtensionRef].Directives.Refs...)
		d.ObjectTypeDefinitions[objectTypeDefinitionRef].HasDirectives = true
	}

	d.Index.MergedTypeExtensions = append(d.Index.MergedTypeExtensions, Node{Ref: objectTypeExtensionRef, Kind: NodeKindObjectTypeExtension})
}
