package ast

import (
	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

type UnionTypeExtension struct {
	ExtendLiteral position.Position
	UnionTypeDefinition
}

func (d *Document) UnionTypeExtensionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.UnionTypeExtensions[ref].Name)
}

func (d *Document) UnionTypeExtensionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.UnionTypeExtensions[ref].Name))
}

func (d *Document) UnionTypeExtensionDescriptionBytes(ref int) ByteSlice {
	if !d.UnionTypeExtensions[ref].Description.IsDefined {
		return nil
	}
	return d.Input.ByteSlice(d.UnionTypeExtensions[ref].Description.Content)
}

func (d *Document) UnionTypeExtensionDescriptionString(ref int) string {
	return unsafebytes.BytesToString(d.UnionTypeExtensionDescriptionBytes(ref))
}

func (d *Document) UnionTypeExtensionHasUnionMemberTypes(ref int) bool {
	return d.UnionTypeExtensions[ref].HasUnionMemberTypes
}

func (d *Document) UnionTypeExtensionHasDirectives(ref int) bool {
	return d.UnionTypeExtensions[ref].HasDirectives
}

func (d *Document) ExtendUnionTypeDefinitionByUnionTypeExtension(unionTypeDefinitionRef, unionTypeExtensionRef int) {
	if d.UnionTypeExtensionHasDirectives(unionTypeExtensionRef) {
		d.UnionTypeDefinitions[unionTypeDefinitionRef].Directives.Refs = append(d.UnionTypeDefinitions[unionTypeDefinitionRef].Directives.Refs, d.UnionTypeExtensions[unionTypeExtensionRef].Directives.Refs...)
		d.UnionTypeDefinitions[unionTypeDefinitionRef].HasDirectives = true
	}

	if d.UnionTypeExtensionHasUnionMemberTypes(unionTypeExtensionRef) {
		d.UnionTypeDefinitions[unionTypeDefinitionRef].UnionMemberTypes.Refs = append(d.UnionTypeDefinitions[unionTypeDefinitionRef].UnionMemberTypes.Refs, d.UnionTypeExtensions[unionTypeExtensionRef].UnionMemberTypes.Refs...)
		d.UnionTypeDefinitions[unionTypeDefinitionRef].HasUnionMemberTypes = true
	}

	d.Index.MergedTypeExtensions = append(d.Index.MergedTypeExtensions, Node{Ref: unionTypeExtensionRef, Kind: NodeKindUnionTypeExtension})
}

func (d *Document) ImportAndExtendUnionTypeDefinitionByUnionTypeExtension(unionTypeExtensionRef int) {
	d.ImportUnionTypeDefinitionWithDirectives(
		d.UnionTypeExtensionNameString(unionTypeExtensionRef),
		d.UnionTypeExtensionDescriptionString(unionTypeExtensionRef),
		d.UnionTypeExtensions[unionTypeExtensionRef].UnionMemberTypes.Refs,
		d.UnionTypeExtensions[unionTypeExtensionRef].Directives.Refs,
	)
	d.Index.MergedTypeExtensions = append(d.Index.MergedTypeExtensions, Node{Ref: unionTypeExtensionRef, Kind: NodeKindUnionTypeExtension})
}
